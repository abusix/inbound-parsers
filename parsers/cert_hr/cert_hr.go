package cert_hr

import (
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

// LOG_DETAILS regex pattern matching Python version
var logDetailsRegex = regexp.MustCompile(
	`(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{1,})\s+\d{1,}\.\d{1,} ` +
		`([^\s]+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,})\s+->\s+` +
		`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,})\s+\..*S\.\s+\d{1,}\s+(\d{1,})\s+(\d{1,})`,
)

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	subjectLower := strings.ToLower(subject)

	var eventsList []*events.Event
	var err error

	if strings.Contains(subjectLower, "portscan") {
		eventsList, err = parsePortScan(body)
	} else if strings.Contains(subjectLower, "ddos") {
		eventsList, err = parseDDoS(serializedEmail)
	} else {
		return nil, common.NewNewTypeError("adapt the parser")
	}

	if err != nil {
		return nil, err
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return eventsList, nil
}

func parsePortScan(body string) ([]*events.Event, error) {
	var eventsList []*events.Event
	regexApplied := false

	lines := common.GetBlockAround(body, "Date first seen")

	for _, line := range lines {
		// Check if line contains an IP
		if common.ExtractOneIP(line) == "" {
			continue
		}

		matches := logDetailsRegex.FindStringSubmatch(line)
		if matches == nil || len(matches) < 9 {
			continue
		}

		regexApplied = true

		// Extract matched groups
		dateTime := matches[1]
		protocol := matches[2]
		srcIP := matches[3]
		srcPort := matches[4]
		targetIP := matches[5]
		targetPort := matches[6]
		packetCount := matches[7]
		byteCount := matches[8]

		event := events.NewEvent("cert_hr")
		event.EventTypes = []events.EventType{events.NewPortScan()}

		// Parse event date
		eventDate := parseDateTime(dateTime)
		event.EventDate = eventDate

		event.AddEventDetail(&events.TransportProtocol{Protocol: protocol})

		event.IP = srcIP
		if port, err := common.ParsePort(srcPort); err == nil {
			event.Port = port
		}

		event.AddEventDetail(&events.Target{
			IP:   targetIP,
			Port: targetPort,
		})

		// Parse traffic stats
		packets, _ := common.ParseInt(packetCount)
		bytes, _ := common.ParseInt(byteCount)
		event.AddEventDetail(&events.TrafficStats{
			PacketCount: packets,
			ByteCount:   bytes,
		})

		eventsList = append(eventsList, event)
	}

	if !regexApplied {
		return nil, common.NewParserError("regex did not match, adapt the regex")
	}

	return eventsList, nil
}

func parseDDoS(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	csvFile, err := getCSV(serializedEmail)
	if err != nil {
		return nil, common.NewParserError("CSV attachment not found")
	}

	// Replace spaces with underscores (matching Python behavior)
	csvFile = strings.ReplaceAll(csvFile, " ", "_")

	// Parse CSV
	reader := csv.NewReader(strings.NewReader(csvFile))
	reader.TrimLeadingSpace = true

	records, err := reader.ReadAll()
	if err != nil {
		return nil, common.NewParserError("failed to parse CSV: " + err.Error())
	}

	if len(records) == 0 {
		return nil, common.NewParserError("empty CSV file")
	}

	// First row is headers
	headers := records[0]

	var eventsList []*events.Event
	ipCombinations := make(map[string]bool)

	// Process each data row
	for i := 1; i < len(records); i++ {
		row := records[i]
		if len(row) != len(headers) {
			continue
		}

		// Create map from headers to values
		entry := make(map[string]string)
		for j, header := range headers {
			entry[header] = row[j]
		}

		// Extract required fields
		srcIP, ok1 := entry["source_ip"]
		srcPort, ok2 := entry["source_port"]
		targetIP, ok3 := entry["destination_ip"]
		targetPort, ok4 := entry["destination_port"]
		dateStr, ok5 := entry["datetime"]
		protocol, ok6 := entry["protocol"]
		packetCountStr, ok7 := entry["packets"]
		byteCountStr, ok8 := entry["bytes"]

		if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || !ok7 || !ok8 {
			return nil, common.NewParserError("fieldnames changed, adapt the parser")
		}

		// Create unique combination key
		combination := fmt.Sprintf("%s:%s-%s:%s", srcIP, srcPort, targetIP, targetPort)

		// Skip if we've already seen this combination
		if ipCombinations[combination] {
			continue
		}
		ipCombinations[combination] = true

		event := events.NewEvent("cert_hr")
		event.EventTypes = []events.EventType{events.NewDDoS()}

		event.IP = srcIP
		if port, err := common.ParsePort(srcPort); err == nil {
			event.Port = port
		}

		event.AddEventDetail(&events.Target{
			IP:   targetIP,
			Port: targetPort,
		})

		// Parse event date (replace underscore back to space)
		dateStr = strings.ReplaceAll(dateStr, "_", " ")
		eventDate := parseDateTime(dateStr)
		event.EventDate = eventDate

		event.AddEventDetail(&events.TransportProtocol{Protocol: protocol})

		// Parse traffic stats
		packetCount, _ := common.ParseInt(packetCountStr)
		byteCount, _ := common.ParseInt(byteCountStr)
		event.AddEventDetail(&events.TrafficStats{
			PacketCount: packetCount,
			ByteCount:   byteCount,
		})

		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

func getCSV(serializedEmail *email.SerializedEmail) (string, error) {
	if len(serializedEmail.Parts) < 2 {
		return "", fmt.Errorf("not enough email parts")
	}

	part := serializedEmail.Parts[1]

	// Check if it's a ZIP file
	if part.Headers != nil {
		if contentType, ok := part.Headers["content-type"]; ok {
			if len(contentType) > 0 && strings.Contains(strings.ToLower(contentType[0]), "zip") {
				// Extract from ZIP
				return common.HandleZipPart(part.Body)
			}
		}
	}

	// Return body directly
	switch body := part.Body.(type) {
	case string:
		return body, nil
	case []byte:
		return string(body), nil
	default:
		return "", fmt.Errorf("unexpected part body type")
	}
}

func parseDateTime(dateStr string) *time.Time {
	if dateStr == "" {
		return nil
	}

	// Format: "2024-10-02 12:34:56.123"
	formats := []string{
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05.999999",
		"2006-01-02 15:04:05.999",
		"2006-01-02 15:04:05",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return &t
		}
	}

	return nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
