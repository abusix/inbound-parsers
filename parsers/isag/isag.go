package isag

import (
	"encoding/csv"
	"io"
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

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Check if 'scan' is in body (case-insensitive)
	if !strings.Contains(strings.ToLower(body), "scan") {
		return nil, common.NewNewTypeError(subject)
	}

	// Extract ASN from subject (between "AS" and " ")
	asn := common.FindStringWithoutMarkers(subject, "AS", " ")

	var result []*events.Event
	seen := make(map[string]bool)

	// Get the CSV block around "Event Time"
	eventLog := common.GetBlockAround(body, "\"Event Time\"")
	if len(eventLog) == 0 {
		return nil, common.NewParserError("no event log found")
	}

	// Join the lines into a single string for CSV parsing
	csvData := strings.Join(eventLog, "\n")
	reader := csv.NewReader(strings.NewReader(csvData))
	reader.TrimLeadingSpace = true

	// Read header
	headers, err := reader.Read()
	if err != nil {
		return nil, common.NewParserError("failed to read CSV headers: " + err.Error())
	}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Skip malformed rows
			continue
		}

		// Build a map from headers to values
		row := make(map[string]string)
		for i, value := range record {
			if i < len(headers) {
				row[headers[i]] = value
			}
		}

		// Get Source IP - skip if already seen
		sourceIP := row["Source IP"]
		if sourceIP == "" || seen[sourceIP] {
			continue
		}
		seen[sourceIP] = true

		// Create event
		event := events.NewEvent("isag")
		event.EventTypes = []events.EventType{events.NewPortScan()}
		event.IP = sourceIP

		// Set port from Source Port
		if sourcePort := row["Source Port"]; sourcePort != "" {
			if port, err := common.ParsePort(sourcePort); err == nil {
				event.Port = port
			}
		}

		// Parse event date from Event Time
		if eventTime := row["Event Time"]; eventTime != "" {
			// Try common date formats
			formats := []string{
				"2006-01-02 15:04:05",
				"2006/01/02 15:04:05",
				"01/02/2006 15:04:05",
				"02.01.2006 15:04:05",
				time.RFC3339,
			}
			for _, format := range formats {
				if t, err := time.Parse(format, eventTime); err == nil {
					event.EventDate = &t
					break
				}
			}
		}

		// Add transport protocol
		if protocol := row["Protocol"]; protocol != "" {
			event.EventDetails = append(event.EventDetails, &events.TransportProtocol{
				Protocol: protocol,
			})
		}

		// Add ASN if found
		if asn != "" {
			event.EventDetails = append(event.EventDetails, &events.ASN{
				ASN: asn,
			})
		}

		// Add target information
		targetDomain := row["Target Domain"]
		targetPort := row["Target Port"]
		if targetDomain != "" || targetPort != "" {
			target := &events.Target{}
			if targetDomain != "" {
				target.URL = targetDomain
			}
			if targetPort != "" {
				target.Port = targetPort
			}
			event.EventDetails = append(event.EventDetails, target)
		}

		result = append(result, event)
	}

	if len(result) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
