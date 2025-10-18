package uceprotect

import (
	"encoding/csv"
	"strconv"
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
	// Get the CSV attachment from the ZIP file (parts[1])
	attachment, err := getAttachment(serializedEmail)
	if err != nil {
		return nil, err
	}

	// Parse CSV
	reader := csv.NewReader(strings.NewReader(attachment))
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

		// Skip rows with IP 0.0.0.0
		ip := rowMap["IP"]
		if ip == "0.0.0.0" {
			continue
		}

		event := events.NewEvent("uceprotect")
		event.EventTypes = []events.EventType{events.NewSpam()}
		event.IP = ip

		// Parse event date from LAST IMPACT TIMESTAMP
		if timestampStr := rowMap["LAST IMPACT TIMESTAMP"]; timestampStr != "" {
			timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
			if err == nil {
				eventDate := time.Unix(timestamp, 0)
				event.EventDate = &eventDate
			}
		}

		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no events created from CSV")
	}

	return eventsList, nil
}

func getAttachment(serializedEmail *email.SerializedEmail) (string, error) {
	if len(serializedEmail.Parts) < 2 {
		return "", common.NewParserError("attachment not found")
	}

	// Get the second part (parts[1]) which contains the ZIP attachment
	part := serializedEmail.Parts[1]

	// Extract from ZIP file
	csvContent, err := common.HandleZipPart(part.Body)
	if err != nil {
		return "", common.NewParserError("failed to extract ZIP attachment: " + err.Error())
	}

	return csvContent, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
