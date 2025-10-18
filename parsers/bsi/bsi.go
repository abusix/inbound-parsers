package bsi

import (
	"encoding/csv"
	"fmt"
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

var (
	// Valid sender addresses for BSI emails
	validFroms = map[string]bool{
		"noreply@reports.certbund.net": true,
		"certbund@bsi.bund.de":         true,
		"reports@reports.cert-bund.de": true,
		"noreply@reports.cert-bund.de": true,
	}

	markmonitorURLMatcher  = regexp.MustCompile(`(?:>)?\s+(?:\d+)\s+(?P<url>.+)\n`)
	markmonitorDateMatcher = regexp.MustCompile(`Datum:\s+(?P<date>.+)\n`)
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// Helper function to avoid name conflicts
func newEvent(parser string) *events.Event {
	return events.NewEvent(parser)
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Remove carriage returns from body
	body = common.RemoveCarriageReturn(body)

	// Parse based on subject line
	return p.parseNew(serializedEmail, body, subject)
}

func (p *Parser) parseNew(serializedEmail *email.SerializedEmail, body, subject string) ([]*events.Event, error) {
	lower := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(subject, "\n", ""), "\r", ""))

	// Try to get CSV attachment or inline CSV
	csvReader, _ := p.getCSVReader(serializedEmail, body)

	// Handle different BSI report types based on subject
	switch {
	// RDP brute force
	case strings.Contains(lower, "rdp brute force"):
		return p.parseRDPBruteForce(serializedEmail, body)

	// SSH brute force
	case strings.Contains(lower, "ssh brute-force") || strings.Contains(lower, "ssh brute force"):
		if strings.Contains(body, "Logs:") || strings.Contains(body, "constituency:") {
			return p.parseSSHBruteForceFromLog(body, serializedEmail)
		}
		if csvReader != nil {
			return p.parseFromCSVReader(csvReader, events.NewLoginAttack("", ""), serializedEmail)
		}
		return p.parseSimple(serializedEmail, body, events.NewLoginAttack("", ""))

	// Malware infections
	case strings.Contains(lower, "schadprogramm-infektion"),
		strings.Contains(lower, "infizierte systeme") && strings.Contains(body, "Schadsoftware"),
		strings.Contains(lower, "meldung von inifzierten systemen"):
		return p.parseMalware(serializedEmail, body, lower)

	// Spam
	case strings.Contains(lower, "spam"):
		return p.parseSpam(serializedEmail, body, lower)

	// Phishing
	case strings.Contains(lower, "phishing"):
		// BSI forwards phishlabs mails - would need phishlabs parser
		return nil, fmt.Errorf("phishing reports require phishlabs parser (not yet ported)")

	// Botnet infections
	case strings.Contains(lower, "summary of cyber-attacks"):
		return p.parseBotnetAttack(serializedEmail, body, "\t")

	case strings.Contains(lower, "botnet infections"):
		return p.parseBotnetAttack(serializedEmail, body, ",")

	case strings.Contains(lower, "infizierte home-router") || strings.Contains(lower, "active botnet"):
		return p.parseSimple(serializedEmail, body, events.NewBot(""))

	// Port scanning
	case strings.Contains(lower, "scanning attacks") || strings.Contains(body, "Attrition/Scanning"):
		return p.parseSimple(serializedEmail, body, events.NewPortScan())

	case strings.Contains(body, "Netzwerkscans von Ihrem Netzwerk"):
		return p.parsePortscan(serializedEmail)

	// Open services (multiple cases)
	case strings.Contains(lower, "offene dns-resolver"):
		if csvReader != nil {
			return p.parseFromCSVReader(csvReader, events.NewOpen("dns"), serializedEmail)
		}
		return p.parseSimple(serializedEmail, body, events.NewOpen("dns"))

	case strings.Contains(lower, "offene redis-server"):
		if csvReader != nil {
			return p.parseFromCSVReader(csvReader, events.NewOpen("redis"), serializedEmail)
		}
		return p.parseSimple(serializedEmail, body, events.NewOpen("redis"))

	case strings.Contains(lower, "offene memcached-server"):
		if csvReader != nil {
			return p.parseFromCSVReader(csvReader, events.NewOpen("memcached"), serializedEmail)
		}
		return p.parseSimple(serializedEmail, body, events.NewOpen("memcached"))

	case strings.Contains(lower, "ntp-server"):
		if csvReader != nil {
			return p.parseFromCSVReader(csvReader, events.NewOpen("ntp"), serializedEmail)
		}
		return p.parseSimple(serializedEmail, body, events.NewOpen("ntp"))

	case strings.Contains(lower, "mongodb-server"):
		if csvReader != nil {
			return p.parseFromCSVReader(csvReader, events.NewOpen("mongodb"), serializedEmail)
		}
		return p.parseSimple(serializedEmail, body, events.NewOpen("mongodb"))

	case strings.Contains(lower, "elasticsearch-server"):
		if csvReader != nil {
			return p.parseFromCSVReader(csvReader, events.NewOpen("elasticsearch"), serializedEmail)
		}
		return p.parseSimple(serializedEmail, body, events.NewOpen("elasticsearch"))

	// DDoS
	case strings.Contains(lower, "ddos-angriffe"):
		if csvReader != nil {
			return p.parseFromCSVReader(csvReader, events.NewDDoS(), serializedEmail)
		}
		return p.parseSimple(serializedEmail, body, events.NewDDoS())

	case strings.Contains(lower, "ddos-reflection"):
		return p.parseDDoSReflection(serializedEmail, body)

	// Compromised servers
	case strings.Contains(lower, "kompromittierung ihres netzwerks") || strings.Contains(lower, "web-shell"):
		return p.parseCompromisedServer(serializedEmail, body)

	case strings.Contains(lower, "kompromittierte microsoft-exchange-server"):
		if csvReader != nil {
			return p.parseFromCSVReader(csvReader, events.NewCompromisedMicrosoftExchange(), serializedEmail)
		}
		return p.parseSimple(serializedEmail, body, events.NewCompromisedMicrosoftExchange())

	// MarkMonitor translated reports
	case strings.Contains(lower, "betrügerische website in ihrer rechtsordnung"):
		return p.parseMarkMonitorTranslated(lower, body)

	default:
		// Unknown report type
		return nil, fmt.Errorf("unknown BSI report type in subject: %s (parser needs extension)", subject)
	}
}

// parseSimple extracts IPs from body and creates basic events
func (p *Parser) parseSimple(serializedEmail *email.SerializedEmail, body string, eventType events.EventType) ([]*events.Event, error) {
	body = strings.ToLower(strings.Split(body, "mit freundlichen")[0])
	body = strings.ReplaceAll(body, "[.]", ".")

	// Normalize IP: markers
	if !strings.Contains(body, "ip:") {
		re := regexp.MustCompile(`ip[\S\n\t\v ]*:`)
		body = re.ReplaceAllString(body, "ip:")
	}

	// Extract URL if present
	url := common.FindStringWithoutMarkers(body, "url: ", "")

	// Normalize IP blocks
	body = strings.ReplaceAll(body, "ip:\n\n", "ip:\n")

	// Extract IPs
	ipsMap := make(map[string]bool)
	ipLines := common.GetBlockAround(strings.ReplaceAll(body, ",", "\n"), "ip:")
	for _, line := range ipLines {
		if ip := common.ExtractOneIP(line); ip != "" {
			ipsMap[ip] = true
		}
	}

	// Fallback: try to extract any IP from body
	if len(ipsMap) == 0 {
		if ip := common.ExtractOneIP(body); ip != "" {
			ipsMap[ip] = true
		}
	}

	// Create events
	var results []*events.Event
	dateHeader := ""
	if serializedEmail.Headers != nil {
		if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
			dateHeader = dates[0]
		}
	}

	for ip := range ipsMap {
		event := newEvent("bsi")
		event.EventTypes = []events.EventType{eventType}
		event.IP = ip
		event.URL = url

		// Set event date from email headers
		if dateHeader != "" {
			event.EventDate = email.ParseDate(dateHeader)
		}

		results = append(results, event)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no IPs found in email body")
	}

	return results, nil
}

// parseFromCSVReader parses events from a CSV reader
func (p *Parser) parseFromCSVReader(reader *csv.Reader, eventType events.EventType, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV: %w", err)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("CSV has no records")
	}

	headers := records[0]
	var results []*events.Event

	dateHeader := ""
	if serializedEmail.Headers != nil {
		if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
			dateHeader = dates[0]
		}
	}

	for i := 1; i < len(records); i++ {
		record := records[i]
		entry := make(map[string]string)
		for j, value := range record {
			if j < len(headers) {
				entry[headers[j]] = value
			}
		}

		event := newEvent("bsi")
		event.EventTypes = []events.EventType{eventType}

		// Extract IP (try multiple field names)
		ip := ""
		for _, key := range []string{"IP", "ip", "ip.src"} {
			if val, ok := entry[key]; ok && val != "" {
				// Fix malformed IPs like 208.100.26..245
				parts := strings.Split(val, ".")
				var cleanParts []string
				for _, part := range parts {
					if part != "" {
						cleanParts = append(cleanParts, part)
					}
				}
				ip = strings.Join(cleanParts, ".")
				break
			}
		}
		event.IP = ip

		// Extract timestamp
		eventDate := ""
		for _, key := range []string{"Last seen (UTC)", "timestamp", "timestamp(UTC+0)"} {
			if val, ok := entry[key]; ok && val != "" {
				eventDate = val
				break
			}
		}

		if eventDate != "" {
			event.EventDate = email.ParseDate(eventDate)
		} else if dateHeader != "" {
			event.EventDate = email.ParseDate(dateHeader)
		}

		// Extract port
		for key, val := range entry {
			lowerKey := strings.ToLower(key)
			if (lowerKey == "port" || strings.Contains(lowerKey, "port")) &&
				(strings.Contains(lowerKey, "src") || strings.Contains(lowerKey, "source")) {
				if port, err := common.ParsePort(val); err == nil {
					event.Port = port
				}
			}
		}

		// Add other fields as simple details
		for key, val := range entry {
			lowerKey := strings.ToLower(key)
			// Skip already processed keys
			if lowerKey == "ip" || lowerKey == "timestamp" || lowerKey == "last seen (utc)" {
				continue
			}
			if val != "" {
				event.AddEventDetailSimple(lowerKey, val)
			}
		}

		results = append(results, event)
	}

	return results, nil
}

// getCSVReader attempts to extract CSV data from attachment or email body
func (p *Parser) getCSVReader(serializedEmail *email.SerializedEmail, body string) (*csv.Reader, error) {
	// Try to find CSV attachment
	csvAttachment, err := p.getCSVAttachment(serializedEmail)
	if err == nil && csvAttachment != "" {
		return csv.NewReader(strings.NewReader(csvAttachment)), nil
	}

	// Try to extract CSV from body
	csvContent, err := p.extractCSVFromBody(body)
	if err == nil && csvContent != "" {
		return csv.NewReader(strings.NewReader(csvContent)), nil
	}

	return nil, fmt.Errorf("no CSV data found")
}

// getCSVAttachment recursively searches for a .csv attachment
func (p *Parser) getCSVAttachment(serializedEmail *email.SerializedEmail) (string, error) {
	return common.FindFirstAttachmentWithMimeType(serializedEmail, ".csv")
}

// extractCSVFromBody extracts CSV content embedded in email body
func (p *Parser) extractCSVFromBody(body string) (string, error) {
	// Look for "Format: " marker
	formatToken := "Format: "
	tokenIdx := strings.Index(body, formatToken)

	if tokenIdx == -1 {
		// Try alternative markers
		markers := []string{
			"Affected hosts on your networks:\n\n",
			"Betroffene Systeme in Ihrem Netzbereich:\n\n",
			"Betroffene Systeme:\n",
		}

		for _, marker := range markers {
			tokenIdx = strings.Index(body, marker)
			if tokenIdx != -1 {
				startingAt := body[tokenIdx+len(marker):]
				csvEnd := strings.Index(startingAt, "\n\n")
				if csvEnd == -1 {
					csvEnd = len(startingAt)
				}
				csvContent := strings.TrimSpace(startingAt[:csvEnd])

				// Add quotes if needed
				if !strings.Contains(csvContent, "\"") && strings.Contains(csvContent, ";") {
					lines := strings.Split(csvContent, "\n")
					for i, line := range lines {
						lines[i] = "\"" + strings.ReplaceAll(line, ";", "\",\"") + "\""
					}
					csvContent = strings.Join(lines, "\n")
				}

				return csvContent, nil
			}
		}

		return "", fmt.Errorf("no CSV markers found in body")
	}

	// Extract format line and CSV data
	startingAtFormat := body[tokenIdx+len(formatToken):]
	formatEnd := strings.Index(startingAtFormat, "\n")
	if formatEnd == -1 {
		return "", fmt.Errorf("malformed CSV format line")
	}

	rest := strings.TrimSpace(startingAtFormat[formatEnd:])
	csvEnd := strings.Index(rest, "\n\n")
	if csvEnd == -1 {
		csvEnd = len(rest)
	}

	return strings.TrimSpace(rest[:csvEnd]), nil
}

// Specialized parsing functions for specific BSI report types

func (p *Parser) parseRDPBruteForce(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	var results []*events.Event
	var currentEvent *events.Event

	dateHeader := ""
	if serializedEmail.Headers != nil {
		if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
			dateHeader = dates[0]
		}
	}

	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "IP") {
			// Save previous event
			if currentEvent != nil && currentEvent.IP != "" {
				results = append(results, currentEvent)
			}

			// Start new event
			currentEvent = newEvent("bsi")
			currentEvent.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
			currentEvent.IP = strings.TrimSpace(strings.TrimPrefix(line, "IP"))

			if dateHeader != "" {
				currentEvent.EventDate = email.ParseDate(dateHeader)
			}
		} else if currentEvent != nil {
			if strings.HasPrefix(line, "Domain") {
				parts := strings.SplitN(line, ": ", 2)
				if len(parts) == 2 {
					currentEvent.URL = parts[1]
				}
			} else if strings.HasPrefix(line, "TCP") || strings.HasPrefix(line, "UDP") {
				parts := strings.Split(line, " to port ")
				if len(parts) == 2 {
					protocol := parts[0]
					portParts := strings.Split(parts[1], " blocked at ")
					if len(portParts) > 0 {
						if port, err := common.ParsePort(portParts[0]); err == nil {
							currentEvent.Port = port
						}
					}
					currentEvent.AddEventDetail(&events.TransportProtocol{Protocol: protocol})
				}
			}
		}
	}

	// Save last event
	if currentEvent != nil && currentEvent.IP != "" {
		results = append(results, currentEvent)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no RDP brute force events found")
	}

	return results, nil
}

func (p *Parser) parseDDoSReflection(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	marker := "timestamp;ip.src;"
	startIdx := strings.Index(body, marker)
	if startIdx == -1 {
		return nil, fmt.Errorf("DDoS reflection marker not found")
	}

	csvContent := body[startIdx:]
	reader := csv.NewReader(strings.NewReader(csvContent))
	reader.Comma = ';'

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse DDoS CSV: %w", err)
	}

	if len(records) < 2 {
		return nil, fmt.Errorf("DDoS CSV has insufficient data")
	}

	headers := records[0]
	var results []*events.Event

	for i := 1; i < len(records); i++ {
		record := records[i]
		entry := make(map[string]string)
		for j, val := range record {
			if j < len(headers) {
				entry[headers[j]] = val
			}
		}

		event := newEvent("bsi")
		event.EventTypes = []events.EventType{events.NewDDoS()}

		if timestamp, ok := entry["timestamp"]; ok {
			event.EventDate = email.ParseDate(timestamp)
		}

		if ip, ok := entry["ip.src"]; ok {
			event.IP = ip
		}

		// Look for port in any column with "srcport"
		for key, val := range entry {
			if strings.Contains(key, "srcport") {
				if port, err := common.ParsePort(val); err == nil {
					event.Port = port
				}
				// Extract protocol from key (e.g., "udp.srcport")
				parts := strings.Split(key, ".")
				if len(parts) > 0 {
					event.AddEventDetail(&events.TransportProtocol{Protocol: strings.ToUpper(parts[0])})
				}
				break
			}
		}

		results = append(results, event)
	}

	return results, nil
}

func (p *Parser) parsePortscan(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Try to extract HTML body from parts
	htmlBody := ""
	if serializedEmail.Parts != nil && len(serializedEmail.Parts) > 0 {
		for _, part := range serializedEmail.Parts {
			if strings.Contains(strings.ToLower(fmt.Sprintf("%v", part.Headers)), "html") {
				if body, ok := part.Body.(string); ok {
					htmlBody = body
					break
				}
			}
		}
	}

	if htmlBody == "" {
		return nil, fmt.Errorf("no HTML body found for portscan parsing")
	}

	// Clean up HTML
	htmlBody = strings.ReplaceAll(htmlBody, "<br />", "")
	htmlBody = strings.ReplaceAll(htmlBody, "&nbsp;&nbsp; &nbsp;", ",")

	// Extract portscan entries
	re := regexp.MustCompile(`itime="(?P<date>\S+,\S+)",srcip=(?P<srcip>\S+),dstip=(?P<dstip>\S+),srcport=(?P<srcport>\S+),dstport=(?P<dstport>\S+),attack`)
	matches := re.FindAllStringSubmatch(htmlBody, -1)

	var results []*events.Event
	for _, match := range matches {
		if len(match) < 6 {
			continue
		}

		event := newEvent("bsi")
		event.EventTypes = []events.EventType{events.NewPortScan()}

		// Parse date
		date := strings.ReplaceAll(match[1], ",", " ")
		event.EventDate = email.ParseDate(date)

		event.IP = match[2]

		if port, err := common.ParsePort(match[4]); err == nil {
			event.Port = port
		}

		// Add target information
		target := &events.Target{
			IP: match[3],
		}
		if port, err := common.ParsePort(match[5]); err == nil {
			target.Port = fmt.Sprintf("%d", port)
		}
		event.AddEventDetail(target)

		results = append(results, event)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no portscan events found in HTML")
	}

	return results, nil
}

func (p *Parser) parseSSHBruteForceFromLog(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Find CSV header
	csvHeader := common.GetNonEmptyLineAfter(body, "Logs:")
	if csvHeader == "" {
		csvHeader = common.GetNonEmptyLineAfter(body, "our constituency:")
	}

	if csvHeader == "" {
		return nil, fmt.Errorf("SSH brute force log header not found")
	}

	// Get continuous lines until empty line
	csvLines := common.GetContinuousLinesUntilEmptyLine(body, csvHeader)

	// Parse header fields
	headerFields := strings.Fields(strings.ReplaceAll(csvHeader, ",", " "))

	var results []*events.Event
	seenAddresses := make(map[string]bool)

	for _, line := range csvLines {
		if line == csvHeader {
			continue
		}

		fields := strings.Fields(strings.ReplaceAll(line, ",", " "))
		if len(fields) == 0 {
			continue
		}

		event := newEvent("bsi")
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

		ip, port := "", ""
		for i, field := range fields {
			if i >= len(headerFields) {
				break
			}

			headerField := strings.ToLower(headerFields[i])

			switch {
			case headerField == "ip":
				ip = field
				event.IP = field

			case strings.Contains(headerField, "timestamp"):
				event.EventDate = email.ParseDate(field)

			case strings.Contains(strings.ReplaceAll(headerField, " ", "_"), "source_port"):
				port = field
				if p, err := common.ParsePort(field); err == nil {
					event.Port = p
				}

			case strings.Contains(strings.ReplaceAll(headerField, " ", "_"), "destination_port"):
				event.AddEventDetail(&events.Target{Port: field})
			}
		}

		// Deduplicate by IP:port
		address := ip + ":" + port
		if !seenAddresses[address] {
			seenAddresses[address] = true
			results = append(results, event)
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no SSH brute force events found in logs")
	}

	return results, nil
}

func (p *Parser) parseMalware(serializedEmail *email.SerializedEmail, body, lower string) ([]*events.Event, error) {
	// Extract malware name from subject
	malwareName := common.FindStringWithoutMarkers(lower, "hinweis auf ", "-")
	if malwareName == "" {
		// Try to extract from body
		re := regexp.MustCompile(`Schadsoftware "(.*?)"`)
		matches := re.FindStringSubmatch(body)
		if len(matches) > 1 {
			malwareName = matches[1]
		}
	}

	// Try CSV parsing first
	csvReader, err := p.getCSVReader(serializedEmail, body)
	if err == nil {
		return p.parseMalwareFromCSV(csvReader, malwareName, serializedEmail)
	}

	// Fallback to simple parsing
	return p.parseSimple(serializedEmail, body, events.NewMalware(malwareName))
}

func (p *Parser) parseMalwareFromCSV(reader *csv.Reader, malwareName string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to read malware CSV: %w", err)
	}

	if len(records) < 2 {
		return nil, fmt.Errorf("insufficient malware CSV data")
	}

	headers := records[0]
	var results []*events.Event

	for i := 1; i < len(records); i++ {
		record := records[i]
		entry := make(map[string]string)
		for j, val := range record {
			if j < len(headers) {
				entry[headers[j]] = val
			}
		}

		event := newEvent("bsi")

		// Use malware name from CSV if available, otherwise from subject
		if name, ok := entry["malware"]; ok && name != "" {
			event.EventTypes = []events.EventType{events.NewMalware(name)}
		} else {
			event.EventTypes = []events.EventType{events.NewMalware(malwareName)}
		}

		// Extract victim IP
		for _, key := range []string{"Victim IP", "IP", "ip"} {
			if ip, ok := entry[key]; ok && ip != "" {
				event.IP = strings.ReplaceAll(ip, "[.]", ".")
				break
			}
		}

		// Extract timestamps
		if lastSeen, ok := entry["LastSeen"]; ok && lastSeen != "" {
			event.EventDate = email.ParseDate(lastSeen)
			if firstSeen, ok := entry["FirstSeen"]; ok && firstSeen != "" {
				event.AddEventDetailSimple("first_seen", firstSeen)
			}
		} else if firstSeen, ok := entry["FirstSeen"]; ok && firstSeen != "" {
			event.EventDate = email.ParseDate(firstSeen)
		}

		// Extract C2 server info
		if c2Host, ok := entry["C2 host"]; ok && c2Host != "" {
			c2Host = strings.ReplaceAll(c2Host, "[.]", ".")
			event.AddEventDetailSimple("c2_host", c2Host)
		}

		results = append(results, event)
	}

	return results, nil
}

func (p *Parser) parseSpam(serializedEmail *email.SerializedEmail, body, lower string) ([]*events.Event, error) {
	event := newEvent("bsi")
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Extract IP from body
	bodyNoNewlines := strings.ReplaceAll(body, "\n", "")
	ip := common.FindStringWithoutMarkers(strings.ToLower(bodyNoNewlines), "host ", " ")
	if ip == "" {
		ip = common.FindStringWithoutMarkers(strings.ToLower(bodyNoNewlines), "(", ")")
	}
	event.IP = ip

	// Set date from email headers
	if serializedEmail.Headers != nil {
		if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
			event.EventDate = email.ParseDate(dates[0])
		}
	}

	return []*events.Event{event}, nil
}

func (p *Parser) parseBotnetAttack(serializedEmail *email.SerializedEmail, body, separator string) ([]*events.Event, error) {
	// Find start marker
	startMarker := ""
	if strings.Contains(body, "Botnet-Aktivitäten informiert:") {
		startMarker = "Botnet-Aktivitäten informiert:"
	} else if strings.Contains(body, "take the appropriate steps.") {
		startMarker = "take the appropriate steps."
	} else {
		return nil, fmt.Errorf("botnet attack start marker not found")
	}

	// Extract timezone from email headers
	timezone := ""
	if serializedEmail.Headers != nil {
		if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
			parts := strings.Split(dates[0], "+")
			if len(parts) > 1 {
				timezone = parts[1]
			}
		}
	}

	// Get block after start marker
	lines := common.GetBlockAround(body, startMarker)

	var results []*events.Event
	seenIPs := make(map[string]bool)

	for _, line := range lines {
		parts := strings.Split(line, separator)
		if len(parts) < 4 {
			continue
		}

		dateStr := strings.TrimSpace(parts[0])
		ip := strings.TrimSpace(parts[1])
		portStr := strings.TrimSpace(parts[2])
		botType := strings.TrimSpace(parts[3])

		if seenIPs[ip] {
			continue
		}
		seenIPs[ip] = true

		event := newEvent("bsi")
		event.EventTypes = []events.EventType{events.NewBot(botType)}
		event.IP = ip

		if port, err := common.ParsePort(portStr); err == nil {
			event.Port = port
		}

		// Parse date
		dateParts := strings.Split(dateStr, " ")
		if len(dateParts) == 2 {
			datePart := dateParts[0]
			timePart := dateParts[1]

			var year, month, day string
			if strings.Contains(datePart, ".") {
				// German format: DD.MM.YYYY
				dayMonthYear := strings.Split(datePart, ".")
				if len(dayMonthYear) == 3 {
					day = dayMonthYear[0]
					month = dayMonthYear[1]
					year = dayMonthYear[2]
				}
			} else if strings.Contains(datePart, "-") {
				// ISO format: YYYY-MM-DD
				yearMonthDay := strings.Split(datePart, "-")
				if len(yearMonthDay) == 3 {
					year = yearMonthDay[0]
					month = yearMonthDay[1]
					day = yearMonthDay[2]
				}
			}

			if year != "" && month != "" && day != "" {
				dateTimeStr := fmt.Sprintf("%s-%s-%s %s", year, month, day, timePart)
				if timezone != "" {
					dateTimeStr += " +" + timezone
				}
				event.EventDate = email.ParseDate(dateTimeStr)
			}
		}

		// Add reporter email if present (6th field)
		if len(parts) > 5 && strings.TrimSpace(parts[5]) != "" {
			org := &events.Organisation{
				Name:         "reporter",
				ContactEmail: strings.TrimSpace(parts[5]),
			}
			event.AddEventDetail(org)
		}

		results = append(results, event)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no botnet attack events found")
	}

	return results, nil
}

func (p *Parser) parseCompromisedServer(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	event := newEvent("bsi")
	event.EventTypes = []events.EventType{events.NewCompromisedServer()}

	// Set date from email headers
	if serializedEmail.Headers != nil {
		if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
			event.EventDate = email.ParseDate(dates[0])
		}
	}

	// Extract IP
	ip := common.GetNonEmptyLineAfter(body, "IP-Adresse in Ihrem Netzwerk")
	if ip == "" {
		ip = common.GetNonEmptyLineAfter(body, "IP-Adresse:")
	}
	event.IP = ip

	// Extract C&C server
	ccServer := common.FindStringWithoutMarkers(body, "-Kontrollserver (", ")")
	ccServer = strings.ReplaceAll(ccServer, "[", "")
	ccServer = strings.ReplaceAll(ccServer, "]", "")

	if ccServer != "" {
		event.AddEventDetailSimple("cc_server", ccServer)
	}

	return []*events.Event{event}, nil
}

func (p *Parser) parseMarkMonitorTranslated(subject, body string) ([]*events.Event, error) {
	// Extract URLs
	matches := markmonitorURLMatcher.FindAllStringSubmatch(body, -1)
	urlsMap := make(map[string]bool)
	for _, match := range matches {
		if len(match) > 1 {
			urlsMap[match[1]] = true
		}
	}

	// Extract date
	dateMatch := markmonitorDateMatcher.FindStringSubmatch(body)
	if len(dateMatch) < 2 {
		return nil, fmt.Errorf("MarkMonitor date not found")
	}

	dateStr := strings.ReplaceAll(dateMatch[1], ".", "/")

	var results []*events.Event
	for url := range urlsMap {
		event := newEvent("bsi")
		event.IP = subject // IP is in the subject
		event.URL = url
		event.EventTypes = []events.EventType{events.NewPhishing()}

		event.EventDate = email.ParseDate(dateStr)

		results = append(results, event)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no URLs found in MarkMonitor report")
	}

	return results, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
