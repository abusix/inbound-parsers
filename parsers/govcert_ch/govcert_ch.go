package govcert_ch

import (
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// customDialect represents CSV dialect with no quote character
type customDialect struct{}

func (c *customDialect) NewReader(data string) *csv.Reader {
	reader := csv.NewReader(strings.NewReader(data))
	reader.Comma = ','
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = false
	return reader
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

	subjectLower := strings.ToLower(subject)

	// Case 1: Infizierte IoT devices
	if strings.Contains(subjectLower, "infizierte iot devices") {
		return p.parseInfectedIoT(serializedEmail, body)
	}

	// Case 2: Leaked credentials
	if strings.Contains(subjectLower, "leaked credentials") {
		return p.parseLeakedCredentials(serializedEmail)
	}

	// Case 3: CSV format with specific header
	if strings.Contains(body, "# Timestamp,ClientIP,ServerIP,Domainname,ClientPort,ServerPort") {
		return p.parseCSVFormat(body)
	}

	// Case 4: Phishing site
	if strings.Contains(subjectLower, "phishing site") {
		return p.parsePhishingSite(body)
	}

	// Case 5: CVE vulnerability
	cvePattern := regexp.MustCompile(`(?i)(cve-\S+) vulnerability`)
	if matches := cvePattern.FindStringSubmatch(body); matches != nil {
		return p.parseCVE(serializedEmail, body, matches[1])
	}

	// Case 6: Infected IPs with base64 attachment
	if strings.Contains(subjectLower, "infected ips") {
		return p.parseInfectedIPs(serializedEmail, subject, body)
	}

	// Case 7: Default - CSV attachment in parts
	return p.parseDefaultCSV(serializedEmail)
}

// parseInfectedIoT handles "Infizierte IoT devices" emails
func (p *Parser) parseInfectedIoT(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	malwareName := common.FindStringWithoutMarkers(body, "namens ", " ")
	asNumber := common.FindStringWithoutMarkers(body, "AS", " ")

	if len(serializedEmail.Parts) < 2 {
		return nil, common.NewParserError("expected at least 2 parts for infected IoT")
	}

	// Get body from second part
	partBody, err := getPartBody(serializedEmail.Parts[1])
	if err != nil {
		return nil, err
	}

	lines := strings.Split(partBody, "\n")
	var result []*events.Event

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		event := events.NewEvent("govcert_ch")
		event.EventTypes = []events.EventType{events.NewMalware(malwareName)}
		if asNumber != "" {
			event.AddEventDetail(&events.ASN{ASN: asNumber})
		}
		event.IP = line
		// Note: Python has event.event_date = line which seems wrong, using header date instead
		if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
			event.EventDate = email.ParseDate(dateHeader[0])
		}
		result = append(result, event)
	}

	return result, nil
}

// parseLeakedCredentials handles "leaked credentials" emails
func (p *Parser) parseLeakedCredentials(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Navigate to parts[0]['parts'][1]['body']
	if len(serializedEmail.Parts) < 1 {
		return nil, common.NewParserError("no parts in email")
	}

	// In Python this is parts[0]['parts'][1], but our structure is flat
	// We need to find the right part with the credentials
	var credBody string
	for _, part := range serializedEmail.Parts {
		body, err := getPartBody(part)
		if err == nil && strings.Contains(body, "@bluewin.ch:") {
			credBody = body
			break
		}
	}

	if credBody == "" {
		return nil, common.NewParserError("could not find credentials in parts")
	}

	lines := strings.Split(credBody, "\n")
	var result []*events.Event

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "@bluewin.ch:") {
			continue
		}

		parts := strings.Split(line, "@bluewin.ch:")
		if len(parts) != 2 {
			continue
		}

		account := parts[0]
		password := parts[1]

		event := events.NewEvent("govcert_ch")
		event.RemoveRequirement("identification")
		event.AddEventDetail(&events.Password{PasswordHash: password})
		event.EventTypes = []events.EventType{events.NewCompromisedAccount(account + "@bluewin.ch:")}

		if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
			event.EventDate = email.ParseDate(dateHeader[0])
		}

		result = append(result, event)
	}

	return result, nil
}

// parseCSVFormat handles CSV format with "# Timestamp,ClientIP,..." header
func (p *Parser) parseCSVFormat(body string) ([]*events.Event, error) {
	// Extract data part by removing "# " prefix from lines
	dataLines := common.GetBlockAround(body, "# ")
	if len(dataLines) == 0 {
		return nil, common.NewParserError("no CSV data found")
	}

	// Strip "# " from each line
	var cleanedLines []string
	for _, line := range dataLines {
		cleaned := strings.TrimPrefix(line, "# ")
		cleanedLines = append(cleanedLines, cleaned)
	}

	csvData := strings.Join(cleanedLines, "\n")

	// Parse CSV with custom dialect (no quoting)
	reader := csv.NewReader(strings.NewReader(csvData))
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = false

	records, err := reader.ReadAll()
	if err != nil {
		return nil, common.NewParserError("failed to parse CSV: " + err.Error())
	}

	if len(records) < 2 {
		return nil, common.NewParserError("CSV has no data rows")
	}

	headers := records[0]
	var result []*events.Event

	// Extract malware name from body (quoted string)
	malwareName := common.FindStringWithoutMarkers(body, "\"", "\"")

	for i := 1; i < len(records); i++ {
		row := records[i]
		entry := make(map[string]string)
		for j, header := range headers {
			if j < len(row) {
				entry[header] = row[j]
			}
		}

		event := events.NewEvent("govcert_ch")
		event.IP = entry["ClientIP"]

		if port := entry["ClientPort"]; port != "" {
			if portInt, err := common.ParsePort(port); err == nil {
				event.Port = portInt
			}
		}

		// Parse date with format like "01.02.2025" -> "01/02/2025"
		if timestamp := entry["Timestamp"]; timestamp != "" {
			timestamp = strings.ReplaceAll(timestamp, ".", "/")
			event.EventDate = email.ParseDate(timestamp)
		}

		event.AddEventDetail(&events.Target{
			IP:   entry["ServerIP"],
			Port: entry["ServerPort"],
			URL:  entry["Domainname"],
		})

		event.EventTypes = []events.EventType{events.NewMalware(malwareName)}
		result = append(result, event)
	}

	return result, nil
}

// parsePhishingSite handles "phishing site" emails
func (p *Parser) parsePhishingSite(body string) ([]*events.Event, error) {
	event := events.NewEvent("govcert_ch")
	event.EventTypes = []events.EventType{events.NewPhishing()}
	event.URL = common.FindStringWithoutMarkers(body, "URL:", "")
	event.IP = common.FindStringWithoutMarkers(body, "IP address:", "")

	detectionDate := common.FindStringWithoutMarkers(body, "Detection date:", "")
	if detectionDate != "" {
		event.EventDate = email.ParseDate(detectionDate)
	}

	return []*events.Event{event}, nil
}

// parseCVE handles CVE vulnerability emails
func (p *Parser) parseCVE(serializedEmail *email.SerializedEmail, body, cveName string) ([]*events.Event, error) {
	// Create event template
	eventTemplate := events.NewEvent("govcert_ch")
	eventTemplate.EventTypes = []events.EventType{events.NewCVE(cveName, "", "")}

	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventTemplate.EventDate = email.ParseDate(dateHeader[0])
	}

	// Extract IP block after "Reverse DNS"
	ipBlock := common.GetBlockAfterWithStop(body, "Reverse DNS", "")
	if len(ipBlock) == 0 {
		return nil, common.NewParserError("no IPs found after 'Reverse DNS'")
	}

	var result []*events.Event
	for _, ip := range ipBlock {
		// Make a copy of the template
		event := *eventTemplate
		event.IP = ip
		result = append(result, &event)
	}

	return result, nil
}

// parseInfectedIPs handles "infected ips" with base64 encoded attachment
func (p *Parser) parseInfectedIPs(serializedEmail *email.SerializedEmail, subject, body string) ([]*events.Event, error) {
	// Extract filename from subject (text in parentheses)
	filename := common.FindStringWithoutMarkers(subject, "(", ")")
	if filename == "" {
		return nil, common.NewParserError("could not extract filename from subject")
	}

	// Find the base64 encoded attachment
	marker := fmt.Sprintf(`Content-Type: text/plain; name="%s.txt"`, strings.ToUpper(filename))
	encodedLines := common.GetBlockAfterWithStop(body, marker, "")
	if len(encodedLines) == 0 {
		return nil, common.NewParserError("couldn't find encoded attachment with relevant data")
	}

	// Decode base64
	var decodedStr string
	for _, line := range encodedLines {
		decoded, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			continue
		}
		decodedStr += string(decoded)
	}

	// Parse the decoded data
	// Format: "01.02.2025 12:34:56 ...,192.168.1.1,botname,10.0.0.1,domain.com,1234,80"
	pattern := regexp.MustCompile(`(?P<timestamp>\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}:\d{2}) .*,(?P<ip>[\d.]+),(?P<botname>[\w+-]+),(?P<dst_ip>[\d.]+),(?P<dst_domain>[\w.]*),(?P<src_port>\d+),(?P<dst_port>\d+)`)

	matches := pattern.FindStringSubmatch(decodedStr)
	if matches == nil {
		return nil, common.NewParserError("could not match pattern in decoded attachment")
	}

	// Extract named groups
	result := make(map[string]string)
	for i, name := range pattern.SubexpNames() {
		if i > 0 && i <= len(matches) {
			result[name] = matches[i]
		}
	}

	event := events.NewEvent("govcert_ch")

	// Parse timestamp: "01.02.2025 12:34:56"
	if timestamp := result["timestamp"]; timestamp != "" {
		t, err := time.Parse("02.01.2006 15:04:05", timestamp)
		if err == nil {
			event.EventDate = &t
		}
	}

	// Set malware type
	if botname := result["botname"]; botname != "" {
		event.EventTypes = []events.EventType{events.NewMalware(botname)}
	} else {
		event.EventTypes = []events.EventType{events.NewMalware("")}
	}

	event.IP = result["ip"]

	if srcPort := result["src_port"]; srcPort != "" {
		if port, err := common.ParsePort(srcPort); err == nil {
			event.Port = port
		}
	}

	event.AddEventDetail(&events.Target{
		IP:   result["dst_ip"],
		Port: result["dst_port"],
		URL:  result["dst_domain"],
	})

	return []*events.Event{event}, nil
}

// parseDefaultCSV handles default case with CSV in parts
func (p *Parser) parseDefaultCSV(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	for _, part := range serializedEmail.Parts {
		// Check if this part has a .txt content-type
		if part.Headers != nil {
			if contentType, ok := part.Headers["content-type"]; ok {
				for _, ct := range contentType {
					if strings.Contains(ct, ".txt") {
						return p.parsePartCSV(serializedEmail, part)
					}
				}
			}
		}
	}

	return nil, common.NewParserError("no .txt attachment found in parts")
}

// parsePartCSV parses CSV data from a part
func (p *Parser) parsePartCSV(serializedEmail *email.SerializedEmail, part email.EmailPart) ([]*events.Event, error) {
	partBody, err := getPartBody(part)
	if err != nil {
		return nil, err
	}

	reader := csv.NewReader(strings.NewReader(partBody))

	records, err := reader.ReadAll()
	if err != nil {
		return nil, common.NewParserError("failed to parse CSV from part: " + err.Error())
	}

	if len(records) < 2 {
		return nil, common.NewParserError("CSV in part has no data rows")
	}

	headers := records[0]
	var result []*events.Event

	for i := 1; i < len(records); i++ {
		row := records[i]
		entry := make(map[string]string)
		for j, header := range headers {
			if j < len(row) {
				entry[header] = row[j]
			}
		}

		event := events.NewEvent("govcert_ch")
		event.IP = entry["ClientIP"]
		event.EventDate = email.ParseDate(entry["# Timestamp"])

		// Determine event type from Botname
		if botname, ok := entry["Botname"]; ok {
			if strings.Contains(botname, "brute-force") {
				event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
			} else if strings.Contains(botname, "conficker") {
				event.EventTypes = []events.EventType{events.NewMalware("conficker")}
			}
		}

		event.AddEventDetail(&events.Target{
			IP:   entry["ServerIP"],
			Port: entry["ServerPort"],
			URL:  entry["Domainname"],
		})

		result = append(result, event)
	}

	return result, nil
}

// getPartBody extracts body from an EmailPart
func getPartBody(part email.EmailPart) (string, error) {
	switch body := part.Body.(type) {
	case string:
		return body, nil
	case []byte:
		return string(body), nil
	default:
		return "", fmt.Errorf("unexpected part body type: %T", body)
	}
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
