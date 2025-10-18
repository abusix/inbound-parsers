package bnshosting

import (
	"encoding/csv"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

// New creates a new Parser instance (for Bento registration)
func New(serializedEmail email.SerializedEmail, fromAddr, fromName, contentType string) *Parser {
	return &Parser{}
}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)
	bodyLower := strings.ToLower(body)

	var eventsList []*events.Event

	// Try to extract HTML table
	var table []string
	var tableErr error

	startMarkers := []string{"please see the logs below", "attacking other networks"}
	for _, marker := range startMarkers {
		startIndex := strings.Index(bodyLower, marker)
		if startIndex != -1 {
			// Try to extract HTML table from the body starting at this position
			if len(serializedEmail.Parts) > 1 {
				if partBody, ok := serializedEmail.Parts[1].Body.(string); ok {
					htmlSection := partBody[startIndex:]
					htmlSection = strings.ReplaceAll(htmlSection, "<th", "<td")
					htmlSection = strings.ReplaceAll(htmlSection, "</th", "</td")
					table, tableErr = common.ExtractHTMLTableAsCSV(htmlSection)
					if tableErr == nil {
						break
					}
				}
			}
		}
	}

	// Check if we found a table in HTML
	info := common.FindStringWithoutMarkers(bodyLower, "please see the logs below", "regards")

	if table != nil {
		// Clean up table data
		for i, row := range table {
			table[i] = regexp.MustCompile(` +`).ReplaceAllString(row, " ")
			table[i] = strings.ToLower(table[i])
			table[i] = strings.ReplaceAll(table[i], " \"", "\"")
			table[i] = strings.ReplaceAll(table[i], "timestamp ", "timestamp")
		}

		// Normalize header
		if len(table) > 0 {
			table[0] = normalizeHeaderFields(table[0], false)
		}

		events, err := parseTable(table, body, serializedEmail, true, ',')
		if err == nil {
			eventsList = append(eventsList, events...)
		}
	} else if strings.Contains(bodyLower, "please see the logs below") &&
		info != "" &&
		strings.Contains(info, "datetime") &&
		strings.Contains(info, "sourceip") {
		// Try to extract table from body text
		events, err := extractTableAsCSVFromBody(serializedEmail, body)
		if err == nil {
			eventsList = append(eventsList, events...)
		}
	} else if strings.Contains(subjectLower, "spoofing") {
		// Parse malicious activity
		events := parseMaliciousActivity(serializedEmail, body)
		eventsList = append(eventsList, events...)
	} else {
		// Parse login attack without table
		events := parseLoginAttackNoTable(serializedEmail, body, subject)
		eventsList = append(eventsList, events...)
	}

	return eventsList, nil
}

// parseTable parses CSV table data and creates events
func parseTable(table []string, body string, serializedEmail *email.SerializedEmail, oldTableFormat bool, delimiter rune) ([]*events.Event, error) {
	// Default timezone (Bangladesh Time)
	zone := "BDT"
	if strings.Contains(body, "GMT") && !strings.Contains(body, "GMT +8") {
		return nil, fmt.Errorf("could not determine timezone, update parser")
	}

	var eventsList []*events.Event

	// Join table rows and parse as CSV
	csvData := strings.Join(table, "\n")
	reader := csv.NewReader(strings.NewReader(csvData))
	reader.Comma = delimiter
	reader.LazyQuotes = true

	records, err := reader.ReadAll()
	if err != nil || len(records) == 0 {
		return nil, err
	}

	headers := records[0]

	for i := 1; i < len(records); i++ {
		row := records[i]
		entry := make(map[string]string)

		for j, value := range row {
			if j < len(headers) {
				entry[headers[j]] = value
			}
		}

		// Skip empty rows
		allEmpty := true
		for _, v := range entry {
			if v != "" {
				allEmpty = false
				break
			}
		}
		if allEmpty {
			continue
		}

		// Parse date
		var date string
		if oldTableFormat {
			if timestamp, ok := entry["timestamp"]; ok && timestamp != "" {
				timestamp = strings.ReplaceAll(timestamp, "t", " ")
				timestamp = strings.ReplaceAll(timestamp, "z", "")
				date = timestamp + " " + zone
			} else if year, ok := entry["year"]; ok {
				month := entry["month"]
				day := entry["day"]
				hour := entry["hour"]
				minute := entry["minute"]

				// Pad with zeros
				if len(day) == 1 {
					day = "0" + day
				}
				if len(hour) == 1 {
					hour = "0" + hour
				}
				if len(minute) == 1 {
					minute = "0" + minute
				}

				date = fmt.Sprintf("%s %s %s %s:%s:00 %s", year, month, day, hour, minute, zone)
			} else if datetime, ok := entry["datetime"]; ok && datetime != "" {
				date = cleanDatetime(datetime) + " " + zone
			}
		} else {
			if datetime, ok := entry["datetime"]; ok && datetime != "" {
				date = datetime + " " + zone
			}
		}

		// Create event
		event := events.NewEvent("bnshosting")

		// Extract source IP
		if srcIP, ok := entry["srcip"]; ok && srcIP != "" {
			if ip := common.IsIP(srcIP); ip != "" {
				event.IP = ip
			}
		}

		// Only create event if we have an IP
		if event.IP != "" {
			event.EventTypes = []events.EventType{events.NewBot("")}

			// Set event date
			if date != "" {
				// Store as string for now - proper date parsing would need timezone handling
				event.EventDetails = append(event.EventDetails, &events.SimpleDetail{
					Key:   "event_date_string",
					Value: date,
				})
			} else if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
				event.EventDetails = append(event.EventDetails, &events.SimpleDetail{
					Key:   "event_date_string",
					Value: dateHeader[0],
				})
			}

			// Add target information if available
			if dstPort, ok := entry["dstport"]; ok && dstPort != "" {
				dstIP := entry["dstip"]
				if port, err := strconv.Atoi(dstPort); err == nil {
					target := &events.Target{
						IP:   dstIP,
						Port: strconv.Itoa(port),
					}
					event.AddEventDetail(target)
				}
			}

			eventsList = append(eventsList, event)
		}
	}

	return eventsList, nil
}

// cleanDatetime cleans up datetime strings
func cleanDatetime(datetime string) string {
	// Remove extra commas (keep only first one)
	parts := strings.Split(datetime, ",")
	if len(parts) > 2 {
		datetime = parts[0] + "," + strings.Join(parts[1:], "")
	}

	// Remove milliseconds (e.g., 2022-07-15t01:30:33.325z)
	datetime = strings.Split(datetime, ".")[0]

	return datetime
}

// parseLoginAttackNoTable parses login attacks without table format
func parseLoginAttackNoTable(serializedEmail *email.SerializedEmail, body, subject string) []*events.Event {
	body = strings.ReplaceAll(body, "\r\n", "\n")
	body = strings.ReplaceAll(body, "\r", "")

	event := events.NewEvent("bnshosting")
	event.EventTypes = []events.EventType{events.NewBot("")}

	// Set event date from email header
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		event.EventDetails = append(event.EventDetails, &events.SimpleDetail{
			Key:   "event_date_string",
			Value: dateHeader[0],
		})
	}

	// Try to extract IP from subject first
	if ip := common.IsIP(subject); ip != "" {
		event.IP = ip
	} else if ip := common.ExtractOneIP(body); ip != "" {
		event.IP = ip
	}

	// Try to extract URL
	if url := common.FindStringWithoutMarkers(body, "URL for this site is:", "\n"); url != "" {
		event.URL = url
	}

	// Only return event if we have IP or URL
	if event.IP != "" || event.URL != "" {
		return []*events.Event{event}
	}

	return nil
}

// parseMaliciousActivity parses malicious activity reports (spoofing)
func parseMaliciousActivity(serializedEmail *email.SerializedEmail, body string) []*events.Event {
	event := events.NewEvent("bnshosting")
	event.EventTypes = []events.EventType{events.NewMaliciousActivity()}

	// Set event date from email header
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		event.EventDetails = append(event.EventDetails, &events.SimpleDetail{
			Key:   "event_date_string",
			Value: dateHeader[0],
		})
	}

	// Extract IP from XML-like markers
	if ipStr := common.FindStringWithoutMarkers(body, "<source_ip>", "</source_ip>"); ipStr != "" {
		if ip := common.IsIP(ipStr); ip != "" {
			event.IP = ip
			return []*events.Event{event}
		}
	}

	return nil
}

// normalizeHeaderFields normalizes CSV header field names
func normalizeHeaderFields(header string, keepHeaderSize bool) string {
	header = strings.ToLower(header)

	// List of field names to normalize (remove spaces)
	names := []string{
		"trigger rule",
		"hostname involved",
		"src port",
		"source port",
		"dest port",
		"destination port",
		"http action",
		"http request",
		"destination ip",
		"dest ip",
		"request_real_IP",
		"src_port",
		"dst_ip",
		"dst_port",
		"request_http_method",
		"request_http_request",
		"response_http_status_code",
		"msg_file",
		"request_apache",
	}

	for _, name := range names {
		if strings.Contains(header, name) {
			if !strings.Contains(name, "_") {
				// Remove spaces
				header = strings.ReplaceAll(header, name, strings.ReplaceAll(name, " ", ""))
			} else {
				// Remove underscores
				header = strings.ReplaceAll(header, name, strings.ReplaceAll(name, "_", ""))
			}
		}
	}

	if keepHeaderSize {
		return header
	}

	// Standardize field names
	header = strings.ReplaceAll(header, "destport", "dstport")
	header = strings.ReplaceAll(header, "destip", "dstip")
	header = strings.ReplaceAll(header, "destinationip", "dstip")
	header = strings.ReplaceAll(header, "sourceip", "srcip")
	header = strings.ReplaceAll(header, "requestrealip", "srcip")
	header = strings.ReplaceAll(header, "date/time", "datetime")

	return header
}

// extractTableAsCSVFromBody extracts table from plain text body
func extractTableAsCSVFromBody(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	// Strip HTML tags from body
	body = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(body, "")

	// Extract info section
	bodyLower := strings.ToLower(body)
	bodyLower = strings.ReplaceAll(bodyLower, "logs below.", "logs below:")

	info := common.FindStringWithoutMarkers(bodyLower, "please see the logs below:", "regards")
	if info == "" {
		return nil, fmt.Errorf("no table info found")
	}

	// Split into lines and clean up
	lines := strings.Split(info, "\n")
	var allLines []string
	for _, line := range lines {
		line = strings.ReplaceAll(line, ">", " ")
		trimmed := strings.TrimSpace(line)
		if len(trimmed) >= 1 {
			allLines = append(allLines, line)
		}
	}

	if len(allLines) == 0 {
		return nil, fmt.Errorf("no table lines found")
	}

	// Check if already in CSV format
	isCSV, separator := checkCSV(allLines)
	if isCSV {
		allLines = fixCSV(allLines, separator)
		if len(allLines) > 0 {
			allLines[0] = normalizeHeaderFields(allLines[0], false)
		}
		return parseTable(allLines, body, serializedEmail, false, rune(separator[0]))
	}

	// Try parsing with aligned headers
	if strings.Contains(bodyLower, "our timezone is") && strings.Contains(bodyLower, "see the logs below:") {
		csvLines := alignedHeadersParsing(allLines)
		if len(csvLines) > 1 {
			return parseTable(csvLines, body, serializedEmail, false, ';')
		}
	}

	// Try unaligned headers parsing
	csvLines := unalignedHeadersParsing(allLines)
	if len(csvLines) > 0 {
		return parseTable(csvLines, body, serializedEmail, false, ';')
	}

	return nil, fmt.Errorf("could not parse table from body")
}

// checkCSV checks if lines are already in CSV format
func checkCSV(lines []string) (bool, string) {
	if len(lines) == 0 {
		return false, ""
	}

	if strings.Contains(lines[0], ",") {
		return true, ","
	} else if strings.Contains(lines[0], ";") {
		return true, ";"
	}

	return false, ""
}

// fixCSV fixes wrongly formatted CSV
func fixCSV(lines []string, separator string) []string {
	if len(lines) == 0 {
		return lines
	}

	headerSize := len(strings.Split(lines[0], separator))
	var refactored []string

	for i, line := range lines {
		lineSize := len(strings.Split(line, separator))
		if lineSize == headerSize {
			refactored = append(refactored, line)
		} else if i < len(lines)-1 {
			// Try merging with next line
			merged := line + lines[i+1]
			if len(strings.Split(merged, separator)) == headerSize {
				refactored = append(refactored, merged)
			}
		}
	}

	return refactored
}

// alignedHeadersParsing parses tables with aligned headers
func alignedHeadersParsing(allLines []string) []string {
	if len(allLines) == 0 {
		return nil
	}

	var csvLines []string
	var allIndexes [][]int

	headerSize := len(allLines[0])

	for i, line := range allLines {
		// Check if headers are aligned with values
		if headerSize-1 <= len(line) && len(line) <= headerSize+1 {
			if i == 0 {
				// Normalize header and find whitespace indices
				line = normalizeHeaderFields(line, true)
				// Find positions where non-whitespace is followed by whitespace
				re := regexp.MustCompile(`\S\s`)
				matches := re.FindAllStringIndex(line, -1)
				for _, match := range matches {
					allIndexes = append(allIndexes, []int{match[0], match[1]})
				}
				newLine := replacer(line, ";", allIndexes, 0)
				newLine = normalizeHeaderFields(newLine, false)
				csvLines = append(csvLines, cleanLine(newLine))
			} else {
				newLine := replacer(line, ";", allIndexes, 0)
				// Remove line number
				index := strings.Index(newLine, " ")
				if index != -1 {
					newLine = newLine[index:]
				}
				csvLines = append(csvLines, cleanLine(newLine))
			}
		}
	}

	return csvLines
}

// unalignedHeadersParsing parses tables with unaligned headers
func unalignedHeadersParsing(allLines []string) []string {
	var csvLines []string

	for i, line := range allLines {
		var newLine string

		if i == 0 {
			line = normalizeHeaderFields(line, false)
		}

		// Find whitespace positions
		re := regexp.MustCompile(`\S\s`)
		matches := re.FindAllStringIndex(line, -1)

		if i == 0 {
			newLine = replacer(line, ";", matches, 0)
		} else {
			// Skip first 2 matches (line number)
			if len(matches) > 2 {
				lineNumberIndex := 0
				if len(matches) > 0 {
					lineNumberIndex = matches[0][1]
				}
				newLine = replacer(line, ";", matches[2:], lineNumberIndex)
			} else {
				newLine = line
			}
		}

		csvLines = append(csvLines, cleanLine(newLine))
	}

	return csvLines
}

// replacer inserts a word at specified indices
func replacer(line, word string, indices [][]int, lineNumberIndex int) string {
	if lineNumberIndex > 0 && lineNumberIndex < len(line) {
		line = line[lineNumberIndex:]
	}

	// Insert word at each index position
	offset := 0
	for _, idx := range indices {
		pos := idx[1] - 1 + offset - lineNumberIndex
		if pos >= 0 && pos < len(line) {
			line = line[:pos] + word + line[pos:]
			offset += len(word)
		}
	}

	return line
}

// cleanLine cleans up a line by removing special characters
func cleanLine(line string) string {
	parts := strings.Split(line, ";")
	for i, part := range parts {
		part = strings.ReplaceAll(part, "\xa0", "")
		part = strings.ReplaceAll(part, "<", "")
		part = strings.ReplaceAll(part, ">", "")
		parts[i] = strings.TrimSpace(part)
	}
	return strings.Join(parts, ";")
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
