// Package abusix implements the Abusix parser for compromised account reports
package abusix

import (
	"encoding/csv"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the Abusix parser
type Parser struct{}

// Parse parses emails from noreply@abusix.org
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get the last attachment (CSV file)
	if len(serializedEmail.Parts) == 0 {
		return nil, common.NewParserError("no attachments found")
	}

	lastPart := serializedEmail.Parts[len(serializedEmail.Parts)-1]
	attachment, err := getPartBody(lastPart)
	if err != nil {
		return nil, err
	}

	// Parse CSV
	reader := csv.NewReader(strings.NewReader(attachment))
	reader.LazyQuotes = true

	// Read all records
	records, err := reader.ReadAll()
	if err != nil {
		return nil, common.NewParserError("failed to parse CSV: " + err.Error())
	}

	if len(records) == 0 {
		return nil, common.NewParserError("empty CSV file")
	}

	// First row is headers
	headers := records[0]
	var pwHashKey string

	// Find password hash column
	for _, header := range headers {
		if strings.HasPrefix(header, "pw_") {
			pwHashKey = header
			break
		}
	}

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

		event := events.NewEvent("abusix")

		// Set event type
		username := rowMap["username"]
		event.EventTypes = []events.EventType{events.NewCompromisedAccount(username)}

		// Add password details
		pwHash := rowMap[pwHashKey]
		hashAlg := ""
		if pwHashKey != "" && len(pwHashKey) > 3 {
			hashAlg = pwHashKey[3:] // Remove "pw_" prefix
		}
		event.AddEventDetail(&events.Password{
			PasswordHash:  pwHash,
			HashAlgorithm: hashAlg,
		})

		// Set IP
		if sourceIP := rowMap["source_ip"]; sourceIP != "" {
			if validIP := common.IsIP(sourceIP); validIP != "" {
				event.IP = validIP
			}
		}

		// Set event date
		if humanDate := rowMap["human_date"]; humanDate != "" {
			eventDate := email.ParseDate(humanDate)
			event.EventDate = eventDate
		}

		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no events created from CSV")
	}

	return eventsList, nil
}

func getPartBody(part email.EmailPart) (string, error) {
	switch body := part.Body.(type) {
	case string:
		return body, nil
	case []byte:
		return string(body), nil
	default:
		return "", common.NewParserError("unexpected part body type")
	}
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
