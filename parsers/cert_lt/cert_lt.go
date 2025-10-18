package cert_lt

import (
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, _ := common.GetSubject(serializedEmail, false)

	// Check subject patterns and route to appropriate parser
	if strings.Contains(subject, "Pažeisti įrenginiai jūsų tinkle") {
		// Damaged devices on your network
		return parseMalware(body)
	}

	if strings.Contains(subject, "Užvaldyti įrenginiai jūsų tinkle") {
		// Occupied devices on your network
		if len(serializedEmail.Parts) > 1 {
			attachment := serializedEmail.Parts[1]
			return parseOccupiedDevices(body, attachment)
		}
		return nil, nil
	}

	if strings.Contains(strings.ToLower(subject), "possible malicious activity from your ip range") {
		return parseLoginAttack(body)
	}

	if len(serializedEmail.Parts) == 2 && strings.Contains(body, "malware") {
		return parseMalwarePart(serializedEmail)
	}

	// Default: Copyright parser
	event := events.NewEvent("cert_lt")

	// Parse event date from headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Extract URL
	url := common.GetNonEmptyLineAfter(body, "Please remove it from public access:")
	if len(url) > 1 && url[1] == '_' {
		// Replace first underscore with 't'
		url = string(url[0]) + "t" + url[2:]
	}
	event.URL = url
	event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}

	if err := event.Validate(); err != nil {
		return nil, &common.ParserError{Message: "no event created"}
	}

	return []*events.Event{event}, nil
}

// findLineNumber finds the line number containing the specified data
func findLineNumber(body, data string) int {
	for number, line := range strings.Split(body, "\n") {
		if strings.Contains(strings.ToLower(line), data) {
			return number
		}
	}
	return -1
}

// getCSVStart finds the start of CSV data by counting keyword occurrences
func getCSVStart(body string) int {
	keywords := []string{
		"asn",
		"ip",
		"timestamp",
		"malware",
		"src_port",
		"dst_port",
		"dst_host",
		"proto",
		"type",
		"observation time",
		"source port",
		"destination ip",
		"domain name",
		"url",
	}

	// Find line numbers for all keywords
	var lineNumbers []int
	for _, keyword := range keywords {
		lineNum := findLineNumber(body, keyword)
		if lineNum >= 0 {
			lineNumbers = append(lineNumbers, lineNum)
		}
	}

	if len(lineNumbers) == 0 {
		return -1
	}

	// Count frequency of each line number
	lineFrequency := make(map[int]int)
	for _, num := range lineNumbers {
		lineFrequency[num]++
	}

	// Find line with maximum keyword count
	maxCount := 0
	maxLine := -1
	for line, count := range lineFrequency {
		if count > maxCount {
			maxCount = count
			maxLine = line
		}
	}

	return maxLine
}

// getCSVPart extracts CSV data from body
func getCSVPart(body string) string {
	start := getCSVStart(body)
	if start < 0 {
		return ""
	}

	split := strings.Split(body, "\n")
	if start >= len(split) {
		return ""
	}

	headers := split[start]

	// Find the CSV part (from header to double newline)
	lineBreak := "\n"
	if strings.Contains(body, "\r\n") {
		lineBreak = "\r\n"
	}
	doubleBreak := lineBreak + lineBreak

	csvPart := common.FindString(body, headers, doubleBreak)
	if csvPart == "" {
		// Try finding until end of file
		idx := strings.Index(body, headers)
		if idx >= 0 {
			csvPart = body[idx:]
		}
	}

	csvPart = strings.TrimSpace(csvPart)

	// Remove line breaks within CSV fields (continuation lines)
	csvPart = strings.ReplaceAll(csvPart, ",\r\n", ", ")
	csvPart = strings.ReplaceAll(csvPart, ",\n", ", ")

	return csvPart
}

// parseCSV parses CSV data into events
func parseCSV(body string, eventType events.EventType, csvPart string) ([]*events.Event, error) {
	if csvPart == "" {
		csvPart = getCSVPart(body)
	}
	if csvPart == "" {
		return nil, &common.ParserError{Message: "no CSV data found"}
	}

	var reader *csv.Reader
	if strings.Contains(csvPart, ",") {
		reader = csv.NewReader(strings.NewReader(csvPart))
		reader.TrimLeadingSpace = true
	} else {
		reader = csv.NewReader(strings.NewReader(csvPart))
		reader.Comma = ' '
	}

	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, &common.ParserError{Message: "no CSV records found"}
	}

	headers := records[0]
	// Normalize headers to lowercase
	for i := range headers {
		headers[i] = strings.ToLower(strings.TrimSpace(headers[i]))
	}

	var result []*events.Event
	for i := 1; i < len(records); i++ {
		row := records[i]
		if len(row) == 0 {
			continue
		}

		event := events.NewEvent("cert_lt")
		if eventType != nil {
			event.EventTypes = []events.EventType{eventType}
		}

		var lastSeen *string
		var targetIP, targetPort, targetURL string
		foundIdentifyingData := false

		for j, value := range row {
			if j >= len(headers) {
				break
			}

			key := headers[j]
			value = strings.TrimSpace(value)

			if value == "" {
				continue
			}

			// Normalize key names
			if key == "dst_ip" {
				key = "target_ip"
			} else if key == "dst_port" {
				key = "target_port"
			} else if key == "proto" {
				key = "protocol"
			} else if key == "malware" {
				key = "malware_type"
			} else if key == "source time" {
				key = "last_seen"
			} else if key == "observation time" {
				key = "timestamp"
			} else if strings.Contains(key, " ") {
				key = strings.ReplaceAll(key, " ", "_")
			}

			// Process fields
			switch key {
			case "ip":
				cleanIP := common.IsIP(value)
				if cleanIP != "" {
					event.IP = cleanIP
					foundIdentifyingData = true
				}

			case "timestamp":
				if event.EventDate != nil {
					lastSeenStr := event.EventDate.Format("2006-01-02 15:04:05")
					lastSeen = &lastSeenStr
				}
				event.EventDate = email.ParseDate(value)

			case "dst_host":
				event.AddEventDetail(&events.Target{URL: value})

			case "last_seen":
				if event.EventDate == nil {
					event.EventDate = email.ParseDate(value)
				}
				lastSeenStr := value
				lastSeen = &lastSeenStr

			case "asn":
				event.AddEventDetail(&events.ASN{ASN: value})

			case "protocol":
				event.AddEventDetail(&events.TransportProtocol{Protocol: value})

			case "malware_type", "malware_family":
				if malware, ok := eventType.(*events.Malware); ok {
					malware.Infection = value
				} else {
					event.EventTypes = []events.EventType{events.NewMalware(value)}
				}

			case "source_port", "src_port":
				if port, err := strconv.Atoi(value); err == nil {
					event.Port = port
				}

			case "target_ip", "destination_ip":
				targetIP = value

			case "target_port", "destination_port":
				targetPort = value

			case "isp":
				event.AddEventDetail(&events.ISP{ISPName: value})

			case "destination_hostname", "destination_domain_name":
				targetURL = value
			}
		}

		// Add target details
		if targetIP != "" || targetPort != "" || targetURL != "" {
			event.AddEventDetail(&events.Target{
				IP:   targetIP,
				Port: targetPort,
				URL:  targetURL,
			})
		}

		// Add evidence with last_seen
		if lastSeen != nil {
			evidence := &events.Evidence{}
			evidence.AddEvidence(events.UrlStore{
				Description: "last_seen",
				URL:         *lastSeen,
			})
			event.AddEventDetail(evidence)
		}

		if !foundIdentifyingData {
			continue // Skip invalid events
		}
		if event.EventDate == nil {
			continue // Skip events without date
		}

		result = append(result, event)
	}

	if len(result) == 0 {
		return nil, &common.ParserError{Message: "no valid events found in CSV"}
	}

	return result, nil
}

// parseMalware parses malware format
func parseMalware(body string) ([]*events.Event, error) {
	lines := common.GetBlockAround(body, "timestamp")
	if len(lines) == 0 {
		return nil, &common.ParserError{Message: "timestamp header not found"}
	}

	header := lines[0]
	header = strings.ReplaceAll(header, "\"", "")
	headerParts := strings.Split(header, ",")

	timestampIndex := -1
	for i, h := range headerParts {
		if strings.Contains(strings.ToLower(h), "timestamp") {
			timestampIndex = i
			break
		}
	}

	dataLine := strings.Join(strings.Fields(common.GetNonEmptyLineAfter(body, "timestamp")), ",")

	if timestampIndex >= 0 {
		dataSplit := strings.Split(dataLine, ",")
		if timestampIndex+1 < len(dataSplit) {
			// Combine timestamp parts
			realTimestamp := fmt.Sprintf("\"%s %s\"", dataSplit[timestampIndex], dataSplit[timestampIndex+1])
			newDataSplit := append(dataSplit[:timestampIndex], realTimestamp)
			newDataSplit = append(newDataSplit, dataSplit[timestampIndex+2:]...)
			dataLine = strings.Join(newDataSplit, ",")
		}
	}

	csvData := header + "\n" + dataLine
	return parseCSV(body, events.NewMalware(""), csvData)
}

// parseOccupiedDevices parses occupied devices format
func parseOccupiedDevices(body string, attachment email.EmailPart) ([]*events.Event, error) {
	var attachmentBody string
	switch b := attachment.Body.(type) {
	case string:
		attachmentBody = b
	case []byte:
		attachmentBody = string(b)
	default:
		return nil, &common.ParserError{Message: "invalid attachment body type"}
	}

	elements := strings.Split(attachmentBody, "\n")
	if len(elements) < 2 {
		return nil, &common.ParserError{Message: "Could not find table headers and rows, has the report format changed?"}
	}

	header := strings.Trim(elements[1], "[]")
	header = strings.ReplaceAll(header, "'", "")
	header = strings.ReplaceAll(header, "date", "timestamp")

	var rows []string
	if len(elements) > 2 {
		rows = elements[2:]
	}

	csvData := header + "\n" + strings.Join(rows, "\n")
	return parseCSV(body, events.NewMalware(""), csvData)
}

// parseLoginAttack parses login attack format
func parseLoginAttack(body string) ([]*events.Event, error) {
	bodyLower := strings.ToLower(body)

	// Extract IPs
	ipLines := common.GetBlockAfterWithStop(bodyLower, "ip addresses", "")
	ipSet := make(map[string]bool)
	for _, line := range ipLines {
		ip := common.ExtractOneIP(line)
		if ip != "" && common.IsIP(ip) != "" {
			ipSet[ip] = true
		}
	}

	// Extract target port
	targetPort := common.FindStringWithoutMarkers(bodyLower, "on port", ".")

	// Extract date
	date := common.FindStringWithoutMarkers(body, "On ", ",")

	var result []*events.Event
	for ip := range ipSet {
		event := events.NewEvent("cert_lt")
		event.IP = ip
		event.EventDate = email.ParseDate(date)
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

		if targetPort != "" {
			event.AddEventDetail(&events.Target{Port: targetPort})
		}

		result = append(result, event)
	}

	return result, nil
}

// parseMalwarePart parses malware part format
func parseMalwarePart(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	if len(serializedEmail.Parts) < 2 {
		return nil, &common.ParserError{Message: "insufficient parts"}
	}

	var partBody string
	switch b := serializedEmail.Parts[1].Body.(type) {
	case string:
		partBody = b
	case []byte:
		partBody = string(b)
	default:
		return nil, &common.ParserError{Message: "invalid part body type"}
	}

	partBody = strings.ReplaceAll(partBody, ";", ",")
	data := strings.Split(partBody, "\n")

	reader := csv.NewReader(strings.NewReader(strings.Join(data, "\n")))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, &common.ParserError{Message: "no CSV records"}
	}

	headers := records[0]
	ipSet := make(map[string]bool)
	var result []*events.Event

	for i := 1; i < len(records); i++ {
		row := records[i]

		var date *string
		var entryIPs []string
		var eventType events.EventType
		var transportProtocol *events.TransportProtocol

		for j, value := range row {
			if j >= len(headers) {
				break
			}

			key := headers[j]
			value = strings.TrimSpace(value)

			if strings.Contains(key, "time") {
				date = &value
			} else if strings.Contains(key, "source.ip") {
				if value != "" && !ipSet[value] {
					ipSet[value] = true
					entryIPs = append(entryIPs, value)
				}
			} else if strings.Contains(key, "classification") {
				if value == "http" {
					eventType = events.NewExploit()
					transportProtocol = &events.TransportProtocol{Protocol: value}
				} else if strings.Contains(value, "ssh") || strings.Contains(value, "telnet") || strings.Contains(value, "ics") {
					eventType = events.NewLoginAttack("", "")
					transportProtocol = &events.TransportProtocol{Protocol: value}
				} else if strings.Contains(value, "blacklisted") {
					eventType = events.NewBlacklist("")
				} else {
					eventType = events.NewMalware(value)
				}
			}
		}

		for _, ip := range entryIPs {
			event := events.NewEvent("cert_lt")
			if eventType != nil {
				event.EventTypes = []events.EventType{eventType}
			}
			if date != nil {
				event.EventDate = email.ParseDate(*date)
			}
			event.IP = ip
			if transportProtocol != nil {
				event.AddEventDetail(transportProtocol)
			}

			result = append(result, event)
		}
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
