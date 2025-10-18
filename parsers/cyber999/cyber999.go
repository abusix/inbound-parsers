package cyber999

import (
	"encoding/csv"
	"strings"

	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, common.NewParserError("failed to get email body: " + err.Error())
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, common.NewParserError("failed to get email subject: " + err.Error())
	}

	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)

	// Check for expected content
	if !strings.Contains(bodyLower, "compromised ip") {
		return nil, common.NewNewTypeError("adapt the parser")
	}

	// Extract external ID from subject
	externalID := common.FindStringWithoutMarkers(subjectLower, "mycert-", "-")

	// Get logs from the second part (attachment)
	if len(serializedEmail.Parts) < 2 {
		return nil, common.NewParserError("logs not found adapt the parser")
	}

	secondPart := serializedEmail.Parts[1]

	// Check if it's a .txt attachment
	if secondPart.Headers != nil {
		if disposition, ok := secondPart.Headers["content-disposition"]; ok {
			if len(disposition) > 0 && !strings.Contains(disposition[0], ".txt") {
				return nil, common.NewParserError("logs not found adapt the parser")
			}
		}
	}

	// Get attachment body
	var logs string
	switch body := secondPart.Body.(type) {
	case string:
		logs = body
	case []byte:
		logs = string(body)
	default:
		return nil, common.NewParserError("logs not found adapt the parser")
	}

	// Extract CSV data between BEGIN-LOG and END-LOG markers
	csvPart := common.FindStringWithoutMarkers(logs, "BEGIN-LOG", "END-LOG")
	csvPart = strings.Trim(csvPart, "-\r\n")

	// Parse CSV
	reader := csv.NewReader(strings.NewReader(csvPart))
	reader.LazyQuotes = true

	records, err := reader.ReadAll()
	if err != nil {
		return nil, common.NewParserError("failed to parse CSV: " + err.Error())
	}

	if len(records) == 0 {
		return nil, common.NewParserError("no event created")
	}

	// First row is headers
	headers := records[0]
	var eventsList []*events.Event

	// Process each data row
	for i := 1; i < len(records); i++ {
		row := records[i]
		if len(row) != len(headers) {
			continue // Skip malformed rows
		}

		// Create map from headers to values
		rowMap := make(map[string]string)
		for j, header := range headers {
			rowMap[header] = row[j]
		}

		event := events.NewEvent("cyber999")

		// Set event date
		if timestamp := rowMap["timestamp"]; timestamp != "" {
			eventDate := email.ParseDate(timestamp)
			event.EventDate = eventDate
		}

		// Set event type
		event.EventTypes = []events.EventType{events.NewCompromisedServer()}

		// Set IP
		if srcIP := rowMap["src_ip"]; srcIP != "" {
			event.IP = srcIP
		}

		// Set port
		if srcPort := rowMap["src_port"]; srcPort != "" {
			if port, err := common.ParsePort(srcPort); err == nil {
				event.Port = port
			}
		}

		// Add transport protocol
		if protocol := rowMap["protocol"]; protocol != "" {
			event.AddEventDetail(&events.TransportProtocol{
				Protocol: protocol,
			})
		}

		// Add ASN
		if srcASN := rowMap["src_asn"]; srcASN != "" {
			event.AddEventDetail(&events.ASN{
				ASN: srcASN,
			})
		}

		// Add external ID
		if externalID != "" {
			event.AddEventDetail(&events.ExternalID{
				ID: externalID,
			})
		}

		// Add target information
		if dstIP := rowMap["dst_ip"]; dstIP != "" || rowMap["dst_port"] != "" {
			event.AddEventDetail(&events.Target{
				IP:   dstIP,
				Port: rowMap["dst_port"],
			})
		}

		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
