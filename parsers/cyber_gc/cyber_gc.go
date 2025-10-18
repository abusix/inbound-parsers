// Package cyber_gc implements the Canadian Cyber Centre parser
package cyber_gc

import (
	"encoding/csv"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the cyber_gc parser
type Parser struct{}

// Parse parses emails from Canadian Cyber Centre (@cyber.gc.ca, @ops.cyber.gc.ca)
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	bodyLower := strings.ToLower(body)

	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	// Get from address for routing logic
	fromAddr := ""
	if from, ok := serializedEmail.Headers["from"]; ok && len(from) > 0 {
		fromAddr = strings.ToLower(from[0])
	}

	var eventsList []*events.Event

	// Check for JSON download URL (@ops.cyber.gc.ca or 'json:' in body)
	if strings.Contains(fromAddr, "@ops.cyber.gc.ca") || strings.Contains(bodyLower, "json:") {
		bodyRaw, _ := common.GetBody(serializedEmail, true)
		downloadURL := common.FindStringWithoutMarkers(bodyRaw, "JSON: ", "")
		if downloadURL != "" {
			// TODO: Implement JSON download and parsing (parse_downloadable_json)
			return nil, common.NewParserError("JSON download parsing not yet implemented")
		}
	}

	// Route to appropriate parsing function based on body content
	if strings.Contains(bodyLower, "malware") {
		csvReaders, _ := getCSVOrXLSXReaders(serializedEmail)
		if len(csvReaders) > 0 {
			for _, csvReader := range csvReaders {
				events := parseMalwareCSV(serializedEmail, csvReader)
				eventsList = append(eventsList, events...)
			}
		} else {
			events := parseMalware(serializedEmail, bodyLower)
			eventsList = append(eventsList, events...)
		}
	} else if strings.Contains(bodyLower, "ssh brute force") {
		events := parseLoginAttack(bodyLower)
		eventsList = append(eventsList, events...)
	} else if strings.Contains(bodyLower, "phishing") {
		events := parsePhishing(serializedEmail, bodyLower)
		eventsList = append(eventsList, events...)
	} else if strings.Contains(subjectLower, "fraud") {
		events := parseFraud(serializedEmail, bodyLower)
		eventsList = append(eventsList, events...)
	} else if strings.Contains(bodyLower, "web attack") {
		events := parseWebAttack(serializedEmail)
		eventsList = append(eventsList, events...)
	} else if csvReaders, _ := getCSVOrXLSXReaders(serializedEmail); len(csvReaders) > 0 {
		for _, csvReader := range csvReaders {
			events := parseCSV(serializedEmail, bodyLower, csvReader)
			eventsList = append(eventsList, events...)
		}
	} else if strings.Contains(bodyLower, "ddos attack") {
		events := parseDDoS(bodyLower)
		eventsList = append(eventsList, events...)
	} else {
		// Try to parse HTML table
		htmlPart, _ := common.FindFirstAttachmentWithMimeType(serializedEmail, "html")
		if htmlPart != "" {
			csvRows, err := common.ExtractHTMLTableAsCSV(htmlPart)
			if err == nil {
				csvReaders := getCSVReaders(csvRows)
				for _, csvReader := range csvReaders {
					events := parseCSV(serializedEmail, bodyLower, csvReader)
					eventsList = append(eventsList, events...)
				}
			}
		}

		if len(eventsList) == 0 && strings.Contains(bodyLower, "malicious activity") {
			events := parseMaliciousActivity(bodyLower, serializedEmail)
			eventsList = append(eventsList, events...)
		}
	}

	if len(eventsList) == 0 {
		return nil, common.NewNewTypeError("Unable to parse cyber_gc email: " + subject)
	}

	return eventsList, nil
}

// parsePhishing handles phishing reports
func parsePhishing(serializedEmail *email.SerializedEmail, bodyLower string) []*events.Event {
	var eventsList []*events.Event
	urls := common.GetBlockAfterWithStop(bodyLower, "affected system(s)", "")

	for _, url := range urls {
		event := events.NewEvent("cyber_gc")
		event.URL = common.CleanURL(strings.Trim(url, "*- "))
		event.EventDate = getHeaderDate(serializedEmail)
		event.EventTypes = []events.EventType{events.NewPhishing()}
		eventsList = append(eventsList, event)
	}

	return eventsList
}

// getEntryForKeys retrieves value from CSV entry for first matching key
func getEntryForKeys(entry map[string]string, keys []string) string {
	for _, key := range keys {
		if value, ok := entry[key]; ok && value != "" {
			return value
		}
	}
	return ""
}

// parseCSV handles CSV attachments with various event types
func parseCSV(serializedEmail *email.SerializedEmail, bodyLower string, csvReader []map[string]string) []*events.Event {
	var eventsList []*events.Event
	var eventType events.EventType

	// Determine event type from body content
	if strings.Contains(bodyLower, "brute force") {
		eventType = events.NewLoginAttack("", "")
	} else if strings.Contains(bodyLower, " cve") || strings.Contains(bodyLower, "critical vulnerability") {
		eventType = events.NewCVE("", "", "")
	} else if strings.Contains(bodyLower, "botnet") {
		eventType = events.NewBot("")
	} else if strings.Contains(bodyLower, "malicious activity") {
		eventType = events.NewMaliciousActivity()
	} else {
		// Check if any CSV entry has "scan" in values
		hasScan := false
		for _, entry := range csvReader {
			for _, value := range entry {
				if strings.Contains(strings.ToLower(value), "scan") {
					hasScan = true
					break
				}
			}
			if hasScan {
				break
			}
		}
		if hasScan {
			eventType = events.NewPortScan()
		} else {
			return eventsList // Unable to determine type
		}
	}

	for _, entry := range csvReader {
		event := events.NewEvent("cyber_gc")

		// Clone event type for each event
		switch et := eventType.(type) {
		case *events.CVE:
			cveName := getEntryForKeys(entry, []string{"vuln"})
			event.EventTypes = []events.EventType{events.NewCVE(cveName, "", "")}
		case *events.LoginAttack:
			event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
		case *events.Bot:
			event.EventTypes = []events.EventType{events.NewBot("")}
		case *events.MaliciousActivity:
			event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
		case *events.PortScan:
			event.EventTypes = []events.EventType{events.NewPortScan()}
		default:
			event.EventTypes = []events.EventType{et}
		}

		// Extract IP
		ipStr := getEntryForKeys(entry, []string{"src ip", "ip", "scanner ip", "ip address", "host ip", "source ip", "ip victim"})
		if validIP := common.IsIP(ipStr); validIP != "" {
			event.IP = validIP
		}

		// Extract URL
		event.URL = getEntryForKeys(entry, []string{"url"})

		// Extract port
		if portStr := getEntryForKeys(entry, []string{"src port", "source_port", "scanner port"}); portStr != "" {
			if port, err := common.ParsePort(portStr); err == nil {
				event.Port = port
			}
		}

		// Extract target details
		dstPort := getEntryForKeys(entry, []string{"destination_port", "victim port"})
		dstIP := getEntryForKeys(entry, []string{"victim ip", "destination ip", "ip victim"})

		// Don't set dst IP if it's the same as source IP
		if common.ExtractOneIP(dstIP) == event.IP {
			dstIP = ""
		}

		if dstPort != "" || dstIP != "" {
			event.AddEventDetail(&events.Target{
				Port: dstPort,
				IP:   dstIP,
			})
		}

		// Extract ASN
		if asnStr := getEntryForKeys(entry, []string{"asn", "asn number"}); asnStr != "" {
			event.AddEventDetail(&events.ASN{ASN: asnStr})
		}

		// Extract event date
		dateStr := getEntryForKeys(entry, []string{
			"time",
			"timestamp(utc+0)",
			"first @timestamp",
			"last seen",
			"timestamp",
			"\ufefftimestamp",
		})

		if dateStr != "" {
			// Handle special date format: "Mar 15, 2024 @ 12:34:56"
			dateMatch := regexp.MustCompile(`(\w{3} \d+),( \d{4}) @( \d{2}:\d{2}:\d{2})`).FindStringSubmatch(dateStr)
			if len(dateMatch) == 4 {
				monthDay := dateMatch[1]
				year := dateMatch[2]
				timeStr := dateMatch[3]
				dateStr = monthDay + year + timeStr
			}

			if parsedDate := magicDateTimeParse(dateStr); parsedDate != nil {
				event.EventDate = parsedDate
			} else {
				event.EventDate = getHeaderDate(serializedEmail)
			}
		} else {
			event.EventDate = getHeaderDate(serializedEmail)
		}

		// Only add events with valid IP
		if event.IP != "" {
			eventsList = append(eventsList, event)
		}
	}

	return eventsList
}

// parseMalwareCSV handles malware CSV attachments
func parseMalwareCSV(serializedEmail *email.SerializedEmail, csvReader []map[string]string) []*events.Event {
	var eventsList []*events.Event

	for _, entry := range csvReader {
		event := events.NewEvent("cyber_gc")

		// Extract date
		dateStr := getEntryForKeys(entry, []string{"timestamp", "firstseen", "source time", "timestamp(utc)", "timestamp(utc+0)"})
		if dateStr != "" {
			if parsedDate := magicDateTimeParse(dateStr); parsedDate != nil {
				event.EventDate = parsedDate
			} else {
				event.EventDate = getHeaderDate(serializedEmail)
			}
		} else {
			event.EventDate = getHeaderDate(serializedEmail)
		}

		// Extract ASN
		if asnStr := getEntryForKeys(entry, []string{"asn", "asn number", "src asn"}); asnStr != "" {
			event.AddEventDetail(&events.ASN{ASN: asnStr})
		}

		// Extract IP (with defanging)
		ipStr := getEntryForKeys(entry, []string{"ip", "source ip"})
		ipStr = strings.ReplaceAll(ipStr, "[.]", ".")

		// Sometimes the reported IP is in victim_ip field
		var dstIP string
		if common.IsIP(ipStr) == "" {
			ipStr = getEntryForKeys(entry, []string{"victim ip"})
			dstIP = ""
		} else {
			dstIP = getEntryForKeys(entry, []string{"dst_ip", "victim_ip", "victim ip", "destination ip"})
		}

		event.IP = common.IsIP(ipStr)

		// Extract port
		if portStr := getEntryForKeys(entry, []string{"port", "src_port", "source_port"}); portStr != "" {
			if port, err := common.ParsePort(portStr); err == nil {
				event.Port = port
			}
		}

		// Extract destination details
		destPort := getEntryForKeys(entry, []string{"dst_port", "destination_port", "destination port"})
		destPortInt := 0
		if destPort != "" {
			if port, err := strconv.Atoi(destPort); err == nil {
				destPortInt = port
			}
		}

		if dstIP != "" || destPortInt > 0 || entry["dst_host"] != "" {
			target := &events.Target{
				IP:  dstIP,
				URL: entry["dst_host"],
			}
			if destPortInt > 0 {
				target.Port = destPort
			}
			event.AddEventDetail(target)
		}

		// Extract protocol
		if proto := entry["proto"]; proto != "" {
			event.AddEventDetail(&events.TransportProtocol{Protocol: proto})
		}

		// Extract malware name
		malwareName := getEntryForKeys(entry, []string{"malware", "malware family"})
		event.EventTypes = []events.EventType{events.NewMalware(malwareName)}

		// Only add events with IP or URL
		if event.IP != "" || event.URL != "" {
			eventsList = append(eventsList, event)
		}
	}

	return eventsList
}

// parseMalware handles malware reports (non-CSV)
func parseMalware(serializedEmail *email.SerializedEmail, bodyLower string) []*events.Event {
	var eventsList []*events.Event

	// Check for HTML table
	if strings.Contains(bodyLower, "<table") {
		// TODO: Parse table - complex implementation needed
		return eventsList
	}

	// Try regex patterns
	regexes := []string{
		`(?P<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*with (?P<malware>.*) malware.*malicious ip address (?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`,
		`ip address (?P<src_ip>\S+) was likely infected with (?P<malware>.*) malware.*malicious ip address (?P<dst_ip>\S+)`,
		`ip address (?P<src_ip>\S+), likely associated to domain (?P<url>\S+),.*compromised with the (?P<malware>.*) malware.* malicious ip address (?P<dst_ip>\S+)`,
		`ip address (?P<src_ip>.+) is at risk .* distributed by .* ip address (?P<dst_ip>\S+)`,
	}

	for _, regexStr := range regexes {
		re := regexp.MustCompile(regexStr)
		if match := re.FindStringSubmatch(bodyLower); match != nil {
			// Extract named groups
			result := make(map[string]string)
			for i, name := range re.SubexpNames() {
				if i != 0 && name != "" && i < len(match) {
					result[name] = match[i]
				}
			}

			srcIPs := strings.ReplaceAll(result["src_ip"], "[.]", ".")
			for _, ip := range strings.Split(srcIPs, ",") {
				ip = strings.TrimSpace(ip)
				if common.IsIP(ip) != "" {
					event := events.NewEvent("cyber_gc")
					event.EventTypes = []events.EventType{events.NewMalware(result["malware"])}
					event.IP = ip
					event.EventDate = getHeaderDate(serializedEmail)

					dstIP := strings.ReplaceAll(result["dst_ip"], "[.]", ".")
					if dstIP != "" {
						event.AddEventDetail(&events.Target{IP: dstIP})
					}

					if url := result["url"]; url != "" {
						event.URL = url
					}

					eventsList = append(eventsList, event)
				}
			}

			if len(eventsList) > 0 {
				return eventsList
			}
		}
	}

	return eventsList
}

// parseFraud handles fraud reports
func parseFraud(serializedEmail *email.SerializedEmail, bodyLower string) []*events.Event {
	event := events.NewEvent("cyber_gc")
	event.EventDate = getHeaderDate(serializedEmail)
	event.EventTypes = []events.EventType{events.NewFraud()}

	urlStr := common.FindStringWithoutMarkers(bodyLower, "url:", "")
	if idx := strings.Index(urlStr, "<"); idx != -1 {
		urlStr = urlStr[:idx]
	}
	event.URL = common.CleanURL(urlStr)

	ipStr := common.FindStringWithoutMarkers(bodyLower, "ip:", "")
	ipStr = strings.ReplaceAll(ipStr, "[.]", ".")
	event.IP = strings.TrimSpace(ipStr)

	return []*events.Event{event}
}

// parseWebAttack handles web attack reports
func parseWebAttack(serializedEmail *email.SerializedEmail) []*events.Event {
	var eventsList []*events.Event

	csvReaders, _ := getCSVOrXLSXReaders(serializedEmail)
	if len(csvReaders) == 0 {
		// Try to extract from HTML table
		if len(serializedEmail.Parts) > 1 {
			bodyStr := ""
			switch body := serializedEmail.Parts[1].Body.(type) {
			case string:
				bodyStr = body
			case []byte:
				bodyStr = string(body)
			}

			if csvRows, err := common.ExtractHTMLTableAsCSV(bodyStr); err == nil {
				csvReaders = getCSVReaders(csvRows)
			}
		}
	}

	for _, csvReader := range csvReaders {
		for _, entry := range csvReader {
			event := events.NewEvent("cyber_gc")

			dateStr := getEntryForKeys(entry, []string{"timestamp", "timestamp(utc+0)"})
			if parsedDate := magicDateTimeParse(dateStr); parsedDate != nil {
				event.EventDate = parsedDate
			} else {
				event.EventDate = getHeaderDate(serializedEmail)
			}

			// Extract ASN
			asnNum := getEntryForKeys(entry, []string{"asn", "asn number"})
			asnName := getEntryForKeys(entry, []string{"source asn", "src asn"})
			if asnNum != "" || asnName != "" {
				event.AddEventDetail(&events.ASN{ASN: asnNum, ASName: asnName})
			}

			// Extract target
			dstPort := getEntryForKeys(entry, []string{"destination_port", "destination port"})
			dstIP := entry["destination ip"]
			if dstPort != "" || dstIP != "" {
				event.AddEventDetail(&events.Target{Port: dstPort, IP: dstIP})
			}

			// Extract source
			event.IP = getEntryForKeys(entry, []string{"source ip", "ip"})
			if portStr := getEntryForKeys(entry, []string{"source port", "source_port"}); portStr != "" {
				if port, err := common.ParsePort(portStr); err == nil {
					event.Port = port
				}
			}

			event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

			if common.IsIP(event.IP) != "" {
				eventsList = append(eventsList, event)
			}
		}
	}

	return eventsList
}

// parseMaliciousActivity handles malicious activity reports
func parseMaliciousActivity(bodyLower string, serializedEmail *email.SerializedEmail) []*events.Event {
	var eventsList []*events.Event

	// Try regex pattern: "MM/DD/YYYY HH:MM:SS AM/PM ... from ip: IP"
	re := regexp.MustCompile(`(\d+/\d+/\d{4})\s+(\d+:\d+:\d+ \w{2})\s+.*from ip: (\S+)`)
	matches := re.FindAllStringSubmatch(bodyLower, -1)

	if len(matches) > 0 {
		for _, match := range matches {
			if len(match) >= 4 {
				dateStr := match[1]
				timeStr := match[2]
				ip := match[3]

				event := events.NewEvent("cyber_gc")
				event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
				event.IP = ip

				// Parse date: "MM/DD/YYYY HH:MM:SS AM"
				if t, err := time.Parse("1/2/2006 3:04:05 PM", dateStr+" "+timeStr); err == nil {
					event.EventDate = &t
				} else {
					event.EventDate = getHeaderDate(serializedEmail)
				}

				eventsList = append(eventsList, event)
			}
		}
	}

	return eventsList
}

// parseLoginAttack handles SSH brute force attack reports
func parseLoginAttack(bodyLower string) []*events.Event {
	var eventsList []*events.Event
	seen := make(map[string]bool)

	// Pattern: "IP YYYY-MM-DD...###Z SRC_PORT DST_PORT"
	re := regexp.MustCompile(`(\S+)\s+(\d{4}-\d{2}-\d{2}.*)\d{3}z\s+(\d+)\s+(\d+)`)
	matches := re.FindAllStringSubmatch(bodyLower, -1)

	for _, match := range matches {
		if len(match) >= 5 {
			ip := match[1]
			timestamp := match[2]
			srcPort := match[3]
			dstPort := match[4]

			if !seen[ip] {
				seen[ip] = true

				event := events.NewEvent("cyber_gc")
				event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
				event.IP = ip

				if port, err := common.ParsePort(srcPort); err == nil {
					event.Port = port
				}

				event.AddEventDetail(&events.Target{Port: dstPort})

				// Parse timestamp
				if t := magicDateTimeParse(timestamp); t != nil {
					event.EventDate = t
				}

				eventsList = append(eventsList, event)
			}
		}
	}

	return eventsList
}

// parseDDoS handles DDoS attack reports
func parseDDoS(bodyLower string) []*events.Event {
	event := events.NewEvent("cyber_gc")
	event.EventTypes = []events.EventType{events.NewDDoS()}

	srcInfo := common.GetNonEmptyLineAfter(bodyLower, "technical information about the malicious system")
	event.IP = common.ExtractOneIP(srcInfo)

	asnNumber := common.FindStringWithoutMarkers(srcInfo, "asn: ", ",")
	asName := common.FindStringWithoutMarkers(srcInfo, "as: ", ",")
	if asnNumber != "" || asName != "" {
		event.AddEventDetail(&events.ASN{ASN: asnNumber, ASName: asName})
	}

	dstIP := common.ExtractOneIP(common.GetNonEmptyLineAfter(bodyLower, "about the attacked resource:"))
	if dstIP != "" {
		event.AddEventDetail(&events.Target{IP: dstIP})
	}

	// Parse date: "date/time XXX: DD.MM.YYYY XXX HH:MM:SS"
	dateMatch := regexp.MustCompile(`date/time \S+: (\S+ )\S+ (\S+)`).FindStringSubmatch(bodyLower)
	if len(dateMatch) == 3 {
		dateStr := dateMatch[1]
		timeStr := dateMatch[2]
		if t, err := time.Parse("02.01.2006 15:04:05", dateStr+timeStr); err == nil {
			event.EventDate = &t
			return []*events.Event{event}
		}
	}

	return nil
}

// getCSVReaders splits CSV content into multiple readers (handles merged CSVs)
func getCSVReaders(csvRows []string) [][]map[string]string {
	var parts [][]string
	currentPart := []string{}

	for _, line := range csvRows {
		// Check if line is empty (all commas and quotes)
		trimmed := strings.ReplaceAll(line, ",", "")
		trimmed = strings.ReplaceAll(trimmed, "\"", "")
		trimmed = strings.TrimSpace(trimmed)

		if trimmed == "" {
			if len(currentPart) > 0 {
				parts = append(parts, currentPart)
				currentPart = []string{}
			}
		} else {
			// Skip broken default headers
			if len(currentPart) == 0 && strings.Contains(strings.ToLower(line), "column3") {
				continue
			}
			currentPart = append(currentPart, line)
		}
	}

	if len(currentPart) > 0 {
		parts = append(parts, currentPart)
	}

	var result [][]map[string]string
	for _, part := range parts {
		if parsed := parseCSVPart(part); len(parsed) > 0 {
			result = append(result, parsed)
		}
	}

	return result
}

// parseCSVPart parses a CSV part into a slice of maps
func parseCSVPart(lines []string) []map[string]string {
	if len(lines) == 0 {
		return nil
	}

	csvData := strings.Join(lines, "\n")
	reader := csv.NewReader(strings.NewReader(csvData))
	reader.LazyQuotes = true

	records, err := reader.ReadAll()
	if err != nil || len(records) < 2 {
		return nil
	}

	// Normalize headers
	headers := make([]string, len(records[0]))
	for i, h := range records[0] {
		headers[i] = strings.ToLower(strings.TrimSpace(h))
	}

	var result []map[string]string
	for i := 1; i < len(records); i++ {
		row := make(map[string]string)
		for j, value := range records[i] {
			if j < len(headers) {
				row[headers[j]] = value
			}
		}
		result = append(result, row)
	}

	return result
}

// getCSVOrXLSXReaders extracts CSV readers from email attachments
func getCSVOrXLSXReaders(serializedEmail *email.SerializedEmail) ([][]map[string]string, error) {
	// Try CSV attachment first
	if csvPart, err := common.FindFirstAttachmentWithMimeType(serializedEmail, "csv"); err == nil {
		csvRows := strings.Split(csvPart, "\n")
		return getCSVReaders(csvRows), nil
	}

	// TODO: Add XLSX support if needed

	return nil, fmt.Errorf("no CSV or XLSX attachments found")
}

// getHeaderDate extracts date from email headers
func getHeaderDate(serializedEmail *email.SerializedEmail) *time.Time {
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		return email.ParseDate(dateHeaders[0])
	}
	return nil
}

// magicDateTimeParse attempts to parse various date formats
func magicDateTimeParse(dateStr string) *time.Time {
	if dateStr == "" {
		return nil
	}

	dateStr = strings.TrimSpace(dateStr)

	// Common formats
	formats := []string{
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04",
		"2006-01-02",
		"02/01/2006 15:04:05",
		"01/02/2006 15:04:05",
		"Jan 2 2006 15:04:05",
		"Jan 02 2006 15:04:05",
		"2 Jan 2006 15:04:05",
		"02 Jan 2006 15:04:05",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return &t
		}
	}

	// Try email.ParseDate as fallback
	return email.ParseDate(dateStr)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
