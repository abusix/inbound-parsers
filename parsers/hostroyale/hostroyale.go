// Package hostroyale implements the HostRoyale parser
package hostroyale

import (
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/parsers/fail2ban"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the HostRoyale parser
type Parser struct{}

var (
	closedTicketPattern = regexp.MustCompile(`changing the status of your ticket #\d{6} to closed`)
	endMarkerPattern    = regexp.MustCompile(`[a-z0-9]{20}`)
)

// Parse parses emails from abuse@hostroyale.com or support@hostroyale.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	ticketID := parseTicketID(subjectLower)

	if strings.Contains(subjectLower, "notice of ") {
		return parseClaimedInfringement(body, ticketID)
	} else if strings.Contains(subjectLower, "your server") {
		return parseAttack(serializedEmail, ticketID)
	} else if strings.Contains(subjectLower, "attack:") {
		return parseAttackDDoS(serializedEmail, body, ticketID)
	} else if strings.Contains(subjectLower, "copyright infringement") {
		return parseCopyright(body, serializedEmail)
	} else if strings.Contains(subjectLower, "compromised client") {
		return parseCircl(body, "hostroyale")
	} else if containsAny(subjectLower, []string{"reg:abuse report", "reg: abuse complaint", "abuse report", "attn:"}) {
		// Copied report parsing
		if strings.Contains(body, "Problem: Spam emitters") {
			return parseSpamEmitters(serializedEmail, body, ticketID)
		} else if strings.Contains(body, "The following intrusion attempts were detected") {
			f := &fail2ban.Parser{}
			return f.Parse(serializedEmail)
		} else if strings.Contains(body, "CIRCL") {
			return parseCircl(body, "hostroyale")
		} else if strings.Contains(body, "multiple brute-force") {
			return parseBruteForce(body, subject)
		} else if strings.Contains(body, "failed logins") {
			return parseLoginAttack(body)
		} else if strings.Contains(strings.ToLower(body), "authentication failed") {
			dateHeader := ""
			if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
				dateHeader = dateHeaders[0]
			}
			return parseLoginAttackSimple(subjectLower, dateHeader)
		} else if strings.Contains(strings.ToLower(body), "crack our server") {
			dateHeader := ""
			if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
				dateHeader = dateHeaders[0]
			}
			return parseServerLoginAttack(serializedEmail, body, dateHeader, ticketID)
		} else {
			return parseCopiedReport(serializedEmail, body, ticketID)
		}
	} else {
		return nil, common.NewNewTypeError(subjectLower)
	}
}

func parseTicketID(subject string) string {
	if !strings.Contains(subject, "ticket") {
		return ""
	}
	ticketPart := common.FindString(subject, "[ticket", "]")
	if ticketPart == "" {
		return ""
	}
	number := strings.TrimPrefix(ticketPart, "[ticket: ")
	number = strings.TrimSuffix(number, "]")
	return number
}

func parseClaimedInfringement(body, ticketID string) ([]*events.Event, error) {
	event := events.NewEvent("hostroyale")
	lines := strings.Split(body, "\n")
	var copyrightedWork string

	for i := 0; i < len(lines); i++ {
		if strings.Contains(lines[i], "Infringement Details") || strings.Contains(lines[i], "Evidentiary Information:") {
			for j := i + 1; j < len(lines); j++ {
				line := lines[j]
				if strings.TrimSpace(line) == "" {
					break
				}
				if strings.Contains(line, "IP Address: ") {
					event.IP = strings.TrimSpace(strings.Split(line, ": ")[1])
				} else if strings.Contains(line, "Timestamp: ") {
					dateStr := strings.TrimSpace(strings.Split(line, ": ")[1])
					event.EventDate = email.ParseDate(dateStr)
				} else if strings.Contains(line, "Port: ") {
					portStr := strings.TrimSpace(strings.Split(line, ": ")[1])
					if port, err := strconv.Atoi(portStr); err == nil {
						event.Port = port
					}
				} else if strings.Contains(line, "Title: ") || strings.Contains(line, "Work") {
					copyrightedWork = strings.TrimSpace(strings.Split(line, ": ")[1])
				}
			}
			break
		}
	}

	if ticketID != "" {
		event.AddEventDetail(&events.ExternalID{ID: ticketID})
	}

	event.EventTypes = []events.EventType{events.NewCopyright(copyrightedWork, "", "")}
	return []*events.Event{event}, nil
}

func parseAttack(serializedEmail *email.SerializedEmail, ticketID string) ([]*events.Event, error) {
	event := events.NewEvent("hostroyale")

	if subjectHeaders, ok := serializedEmail.Headers["subject"]; ok && len(subjectHeaders) > 0 {
		event.IP = subjectHeaders[0]
	}

	if ticketID != "" {
		event.AddEventDetail(&events.ExternalID{ID: ticketID})
	}

	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	event.EventTypes = []events.EventType{events.NewBot("")}
	return []*events.Event{event}, nil
}

func getNextLogPart(dump string) []string {
	var results []string
	endMarker := "0x"
	started := false
	currentResult := ""

	for _, line := range strings.Split(dump, "\n") {
		lineWithNewline := line + "\n"
		if started && !strings.HasPrefix(line, endMarker) {
			if currentResult != "" {
				results = append(results, currentResult)
			}
			currentResult = lineWithNewline
			started = false
			continue
		}
		if strings.HasPrefix(line, endMarker) {
			started = true
		}
		currentResult += lineWithNewline
	}

	if currentResult != "" {
		results = append(results, currentResult)
	}

	return results
}

func parseTcpdumpOutput(tcpdump string) map[string]string {
	lines := strings.Split(tcpdump, "\n")
	if len(lines) < 2 {
		return nil
	}

	dateLine := strings.Split(lines[0], " IP ")
	if len(dateLine) < 1 {
		return nil
	}
	date := dateLine[0]

	parts := strings.Split(lines[1], " > ")
	if len(parts) < 2 {
		return nil
	}

	sourceIPAndPort := parts[0]
	remainder := parts[1]

	// Split source IP and port
	sourceLastDot := strings.LastIndex(sourceIPAndPort, ".")
	if sourceLastDot == -1 {
		return nil
	}
	sourceIP := sourceIPAndPort[:sourceLastDot]
	sourcePort := sourceIPAndPort[sourceLastDot+1:]

	// Split target IP:port and remainder
	colonSplit := strings.SplitN(remainder, ": ", 2)
	if len(colonSplit) < 2 {
		return nil
	}

	targetIPAndPort := colonSplit[0]
	remainder = colonSplit[1]

	// Split target IP and port
	targetLastDot := strings.LastIndex(targetIPAndPort, ".")
	if targetLastDot == -1 {
		return nil
	}
	targetIP := targetIPAndPort[:targetLastDot]
	targetPort := targetIPAndPort[targetLastDot+1:]

	protocol := strings.Split(remainder, ",")[0]

	return map[string]string{
		"protocol":    protocol,
		"target_ip":   targetIP,
		"target_port": targetPort,
		"source_ip":   sourceIP,
		"source_port": sourcePort,
		"date":        date,
	}
}

func parseAttackDDoS(serializedEmail *email.SerializedEmail, body, ticketID string) ([]*events.Event, error) {
	var evts []*events.Event
	octet := common.FindStringWithoutMarkers(body, `The value of that octet is "`, `".)`)

	if strings.Contains(body, `"tcpdump"`) {
		dump := common.FindStringWithoutMarkers(body, "Date/timestamps (at the very left) are UTC.", "(The final octet")
		if dump == "" {
			event := events.NewEvent("hostroyale")
			event.EventTypes = []events.EventType{events.NewDDoS()}

			if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
				event.EventDate = email.ParseDate(dateHeaders[0])
			}

			if ticketID != "" {
				event.AddEventDetail(&events.ExternalID{ID: ticketID})
			}

			if subjectHeaders, ok := serializedEmail.Headers["subject"]; ok && len(subjectHeaders) > 0 {
				event.IP = subjectHeaders[0]
			}

			return []*events.Event{event}, nil
		}

		// Parse tcpdump output
		for _, logPart := range getNextLogPart(strings.TrimSpace(dump)) {
			data := parseTcpdumpOutput(logPart)
			if data == nil {
				continue
			}

			event := events.NewEvent("hostroyale")
			event.EventTypes = []events.EventType{events.NewDDoS()}
			event.EventDate = email.ParseDate(data["date"])
			event.IP = data["source_ip"]

			if port, err := strconv.Atoi(data["source_port"]); err == nil {
				event.Port = port
			}

			if ticketID != "" {
				event.AddEventDetail(&events.ExternalID{ID: ticketID})
			}

			targetIP := strings.ReplaceAll(data["target_ip"], "x", octet)
			event.AddEventDetail(&events.Target{IP: targetIP, Port: data["target_port"]})
			event.AddEventDetail(&events.TransportProtocol{Protocol: data["protocol"]})

			evts = append(evts, event)
		}
	}

	return evts, nil
}

func parseSpamEmitters(serializedEmail *email.SerializedEmail, body, ticketID string) ([]*events.Event, error) {
	event := events.NewEvent("hostroyale")
	event.EventTypes = []events.EventType{events.NewSpam()}

	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	if ticketID != "" {
		event.AddEventDetail(&events.ExternalID{ID: ticketID})
	}

	if strings.Contains(body, "Problem") {
		problem := common.FindStringWithoutMarkers(body, "Problem:", "")
		if problem != "" {
			evidence := &events.Evidence{}
			evidence.AddEvidence(events.UrlStore{Description: "problem", URL: problem})
			event.AddEventDetail(evidence)
		}
	}

	ipFound := false
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				if strings.Contains(key, "IP address") {
					ipFound = true
					event.IP = value
					break
				}
			}
		}
	}

	if !ipFound {
		return nil, common.NewParserError("no ip found")
	}

	return []*events.Event{event}, nil
}

func parseCopyright(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	event := events.NewEvent("hostroyale")
	data := strings.ReplaceAll(body, "> ", "")

	// Basic copyright parser - extract key-value pairs
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.ToLower(strings.TrimSpace(parts[0]))
				value := strings.TrimSpace(parts[1])

				switch {
				case strings.Contains(key, "ip") && !strings.Contains(key, "timestamp"):
					event.IP = value
				case strings.Contains(key, "port"):
					if port, err := strconv.Atoi(value); err == nil {
						event.Port = port
					}
				case strings.Contains(key, "timestamp") || strings.Contains(key, "date"):
					event.EventDate = email.ParseDate(value)
				}
			}
		}
	}

	if event.EventDate == nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}
	return []*events.Event{event}, nil
}

func parseBruteForce(body, subject string) ([]*events.Event, error) {
	var evts []*events.Event

	ipsStr := common.FindStringWithoutMarkers(body, "IP'", ". ")
	ipsStr = strings.TrimSpace(ipsStr)
	ips := strings.Split(ipsStr, ", ")

	dateStr := common.FindStringWithoutMarkers(body, " [", "] \"")
	externalIDStr := common.FindStringWithoutMarkers(subject, "ID:", "]")

	for _, ip := range ips {
		event := events.NewEvent("hostroyale")
		event.IP = ip
		event.EventDate = email.ParseDate(dateStr)
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
		if externalIDStr != "" {
			event.AddEventDetail(&events.ExternalID{ID: externalIDStr})
		}
		evts = append(evts, event)
	}

	return evts, nil
}

func parseLoginAttack(body string) ([]*events.Event, error) {
	event := events.NewEvent("hostroyale")

	ip := common.FindStringWithoutMarkers(body, "Source:", "")
	dateStr := common.FindStringWithoutMarkers(body, "Date:", "")
	user := common.FindStringWithoutMarkers(body, "user=", "")
	portStr := common.FindStringWithoutMarkers(body, "Port:", "")

	event.IP = ip
	event.EventDate = email.ParseDate(dateStr)

	if portStr != "" {
		if port, err := strconv.Atoi(portStr); err == nil {
			event.Port = port
		}
	}

	event.EventTypes = []events.EventType{events.NewLoginAttack(user, "")}
	return []*events.Event{event}, nil
}

func parseLoginAttackSimple(subject, dateHeader string) ([]*events.Event, error) {
	event := events.NewEvent("hostroyale")
	event.IP = subject
	event.EventDate = email.ParseDate(dateHeader)
	event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	return []*events.Event{event}, nil
}

func parseServerLoginAttack(serializedEmail *email.SerializedEmail, body, dateHeader, ticketID string) ([]*events.Event, error) {
	event := events.NewEvent("hostroyale")
	event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

	if subjectHeaders, ok := serializedEmail.Headers["subject"]; ok && len(subjectHeaders) > 0 {
		event.IP = subjectHeaders[0]
	}

	event.EventDate = email.ParseDate(dateHeader)

	targetIPStr := common.FindStringWithoutMarkers(body, "lip=", "")
	targetIPStr = strings.Split(targetIPStr, ",")[0]
	targetIPStr = strings.Split(targetIPStr, " ")[0]

	if targetIPStr != "" {
		event.AddEventDetail(&events.Target{IP: targetIPStr})
	}

	if ticketID != "" {
		event.AddEventDetail(&events.ExternalID{ID: ticketID})
	}

	return []*events.Event{event}, nil
}

func parseCircl(body, parserName string) ([]*events.Event, error) {
	event := events.NewEvent(parserName)

	if !strings.Contains(body, "compromised by a malware") {
		return nil, common.NewNewTypeError("new type in hostroyale circl")
	}

	values := ""
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, "ip") && strings.Contains(line, "timestamp") {
			values = common.FindString(body, line, "\n\n")
			if values == "" {
				values = common.FindString(body, line, "\r\n\r\n")
			}
			break
		}
	}

	if values == "" {
		return nil, common.NewParserError("no data found")
	}

	values = strings.Trim(values, "\n\r")
	values = strings.ReplaceAll(values, ",\r\n", ", ")
	values = strings.ReplaceAll(values, ",\n", ", ")

	var valueLines []string
	if strings.Contains(values, "\r\n") {
		valueLines = strings.Split(values, "\r\n")
	} else {
		valueLines = strings.Split(values, "\n")
	}

	if len(valueLines) < 2 {
		return nil, common.NewParserError("insufficient data lines")
	}

	keys := strings.Split(valueLines[0], ", ")
	vals := strings.Split(valueLines[1], ", ")

	malwareName := ""
	target := &events.Target{}
	event.AddEventDetail(target)

	for i := 0; i < len(keys) && i < len(vals); i++ {
		key := keys[i]
		value := vals[i]

		switch key {
		case "ip":
			event.IP = value
		case "timestamp":
			event.EventDate = email.ParseDate(value)
		case "src_port":
			if port, err := strconv.Atoi(value); err == nil {
				event.Port = port
			}
		case "dst_ip":
			target.IP = value
		case "dst_port":
			target.Port = value
		case "dst_host":
			target.URL = value
		case "proto":
			event.AddEventDetail(&events.TransportProtocol{Protocol: value})
		case "asn":
			event.AddEventDetail(&events.ASN{ASN: value})
		case "malware":
			malwareName = value
		}
	}

	if strings.Contains(body, "compromised by a malware") {
		event.EventTypes = []events.EventType{events.NewMalware(malwareName)}
	} else {
		return nil, common.NewNewTypeError("new type in hostroyale circl")
	}

	return []*events.Event{event}, nil
}

func parseCopiedReport(serializedEmail *email.SerializedEmail, body, ticketID string) ([]*events.Event, error) {
	dataPart := common.GetBlockAround(body, "Protocol")

	if len(dataPart) == 0 {
		// Try HTML part
		if len(serializedEmail.Parts) > 1 {
			htmlBody, _ := common.GetBody(&email.SerializedEmail{
				Body:    serializedEmail.Parts[1].Body,
				Headers: serializedEmail.Parts[1].Headers,
			}, false)

			// Simple HTML strip for text extraction
			htmlBody = stripHTMLTags(htmlBody)
			dataPart = common.GetBlockAround(htmlBody, "Protocol")

			if len(dataPart) > 0 {
				return parseCopiedReportHTMLFormat(dataPart, ticketID)
			}
		}

		return nil, common.NewParserError("Mail format changed, change the parser!")
	}

	// Calculate standard deviation of line lengths
	var lineLengths []float64
	for _, line := range dataPart {
		lineLengths = append(lineLengths, float64(len(line)))
	}

	deviation := stdev(lineLengths)
	if deviation < 10 { // magic number: terrible format
		return parseCopiedReportTerrible(body, ticketID)
	}

	event := events.NewEvent("hostroyale")
	if ticketID != "" {
		event.AddEventDetail(&events.ExternalID{ID: ticketID})
	}

	// Remove surrounding data
	started := false
	var removedSurroundingData []string
	for _, line := range dataPart {
		if !started && !strings.Contains(line, ":") {
			continue
		}
		started = true
		removedSurroundingData = append(removedSurroundingData, line)
	}

	// Handle wrapped lines
	var wrappedDataPart []string
	for i, line := range removedSurroundingData {
		if i == 0 {
			continue
		}
		line = strings.Join(strings.Fields(line), " ")
		if !strings.Contains(line, ":\t") && !strings.Contains(line, ": ") {
			if len(wrappedDataPart) > 0 {
				wrappedDataPart[len(wrappedDataPart)-1] += " " + line
			}
		} else {
			wrappedDataPart = append(wrappedDataPart, line)
		}
	}

	// Build key:data dict
	var keyToData [][]string
	for _, line := range wrappedDataPart {
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) == 2 {
			keyToData = append(keyToData, parts)
		}
	}

	rawEventCopyrightParser(event, keyToData)
	return []*events.Event{event}, nil
}

func parseCopiedReportTerrible(body, ticketID string) ([]*events.Event, error) {
	event := events.NewEvent("hostroyale")
	if ticketID != "" {
		event.AddEventDetail(&events.ExternalID{ID: ticketID})
	}

	lineBreak := "\n"
	if strings.Contains(body, "\r\n") {
		lineBreak = "\r\n"
	}

	dataPart := common.FindString(body, "United States Email", lineBreak+lineBreak)
	if dataPart == "" {
		return nil, common.NewParserError("Mail format changed, change the parser!")
	}
	dataPart = strings.ReplaceAll(dataPart, lineBreak, " ")

	keys := []string{
		"United States Email",
		"Evidentiary Information",
		"Protocol",
		"Infringed Work",
		"Infringing FileName",
		"Infringing FileSize",
		"Infringer's IP Address",
		"Infringer's Port",
		"Initial Infringement Timestamp",
	}

	// Build index map
	type keyIndex struct {
		key   string
		index int
	}
	var keyToIndex []keyIndex
	for _, key := range keys {
		idx := strings.Index(dataPart, key)
		if idx != -1 {
			keyToIndex = append(keyToIndex, keyIndex{key, idx})
		}
	}

	// Sort by index
	for i := 0; i < len(keyToIndex)-1; i++ {
		for j := i + 1; j < len(keyToIndex); j++ {
			if keyToIndex[i].index > keyToIndex[j].index {
				keyToIndex[i], keyToIndex[j] = keyToIndex[j], keyToIndex[i]
			}
		}
	}

	// Add cutoff for the last value
	endMatch := endMarkerPattern.FindStringIndex(dataPart)
	if endMatch != nil {
		keyToIndex = append(keyToIndex, keyIndex{"", endMatch[0]})
	} else {
		keyToIndex = append(keyToIndex, keyIndex{"", len(dataPart)})
	}

	// Build key:data dict
	var keyToData [][]string
	for i := 0; i < len(keyToIndex)-1; i++ {
		key := keyToIndex[i].key
		start := keyToIndex[i].index
		end := keyToIndex[i+1].index

		if key == "" {
			break
		}

		value := dataPart[start+len(key)+1 : end]
		value = strings.TrimSpace(value)
		keyToData = append(keyToData, []string{key, value})
	}

	rawEventCopyrightParser(event, keyToData)
	return []*events.Event{event}, nil
}

func parseCopiedReportHTMLFormat(dataPart []string, ticketID string) ([]*events.Event, error) {
	stripper := "\r\n\t-#> "
	multiline := ""
	var keyValue [][]string
	var keyStack []string

	for _, element := range dataPart {
		if multiline != "" {
			multiline += strings.Split(element, "<")[0]
			if strings.Contains(element, "</") {
				keyValue = append(keyValue, []string{strings.Join(keyStack, "_"), multiline})
				if len(keyStack) > 0 {
					keyStack = keyStack[:len(keyStack)-1]
				}
				multiline = ""
				continue
			}
		}

		if !strings.HasPrefix(element, "<?") && strings.HasPrefix(element, "<") {
			elementKey := strings.Split(strings.Split(element[1:], ">")[0], " ")[0]
			if !strings.HasPrefix(elementKey, "/") {
				keyStack = append(keyStack, elementKey)
				parts := strings.Split(element, ">")
				if len(parts) > 1 {
					value := strings.Split(parts[1], "<")[0]
					if strings.Contains(element, "</") {
						if value != "" {
							keyValue = append(keyValue, []string{strings.Join(keyStack, "_"), value})
						}
						if len(keyStack) > 0 {
							keyStack = keyStack[:len(keyStack)-1]
						}
					} else {
						multiline = value
					}
				}
			} else {
				if len(keyStack) > 0 {
					keyStack = keyStack[:len(keyStack)-1]
				}
			}
		}
	}

	event := events.NewEvent("hostroyale")
	eventType := events.NewCopyright("", "", "")
	if ticketID != "" {
		event.AddEventDetail(&events.ExternalID{ID: ticketID})
	}

	externalCaseInfo := &events.ExternalCaseInformation{}
	file := &events.File{}
	reporter := &events.Organisation{Name: "reporter"}
	provider := &events.Organisation{Name: "provider"}

	for _, kv := range keyValue {
		key := strings.Trim(strings.ToLower(kv[0]), stripper)
		value := strings.Trim(kv[1], stripper)

		switch {
		case strings.Contains(key, "case_id"):
			externalCaseInfo.CaseID = value
		case strings.Contains(key, "case_status"):
			externalCaseInfo.Status = value
		case strings.Contains(key, "case_severity"):
			externalCaseInfo.Severity = value
		case strings.Contains(key, "complainant_entity"):
			reporter.Organisation = value
		case strings.Contains(key, "complainant_contact"):
			reporter.ContactName = value
		case strings.Contains(key, "complainant_address"):
			reporter.Address = value
		case strings.Contains(key, "complainant_phone"):
			reporter.ContactPhone = value
		case strings.Contains(key, "complainant_email"):
			reporter.ContactEmail = value
		case strings.Contains(key, "service_provider_entity"):
			provider.Organisation = value
		case strings.Contains(key, "service_provider_email"):
			provider.ContactEmail = value
		case strings.Contains(key, "source_timestamp"):
			event.EventDate = email.ParseDate(value)
		case strings.Contains(key, "source_ip"):
			event.IP = value
		case strings.Contains(key, "source_port"):
			if port, err := strconv.Atoi(value); err == nil {
				event.Port = port
			}
		case strings.Contains(key, "source_type"):
			eventType.Protocol = value
		case strings.Contains(key, "title"):
			eventType.CopyrightedWork = value
		case strings.Contains(key, "filename"):
			file.FileName = value
		case strings.Contains(key, "filesize"):
			file.FileSize = value
		case strings.Contains(key, "hash"):
			file.FileHash = value
		}
	}

	event.AddEventDetail(externalCaseInfo)
	event.AddEventDetail(file)
	event.AddEventDetail(reporter)
	event.AddEventDetail(provider)
	event.EventTypes = []events.EventType{eventType}

	return []*events.Event{event}, nil
}

func rawEventCopyrightParser(event *events.Event, keyToData [][]string) {
	copyrightType := events.NewCopyright("", "", "")

	for _, kv := range keyToData {
		if len(kv) < 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		value := strings.TrimSpace(kv[1])

		switch {
		case strings.Contains(key, "ip") && !strings.Contains(key, "timestamp"):
			event.IP = value
		case strings.Contains(key, "port") && !strings.Contains(key, "ip"):
			if port, err := strconv.Atoi(value); err == nil {
				event.Port = port
			}
		case strings.Contains(key, "timestamp") || strings.Contains(key, "date"):
			event.EventDate = email.ParseDate(value)
		case strings.Contains(key, "protocol"):
			copyrightType.Protocol = value
		case strings.Contains(key, "work") || strings.Contains(key, "title"):
			copyrightType.CopyrightedWork = value
		}
	}

	event.EventTypes = []events.EventType{copyrightType}
}

// Helper functions

func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

func stripHTMLTags(html string) string {
	// Simple HTML tag stripper
	re := regexp.MustCompile(`<[^>]*>`)
	return re.ReplaceAllString(html, "")
}

func stdev(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	// Calculate mean
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))

	// Calculate variance
	variance := 0.0
	for _, v := range values {
		diff := v - mean
		variance += diff * diff
	}
	variance /= float64(len(values))

	return math.Sqrt(variance)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
