// Package heficed implements the Heficed parser
package heficed

import (
	"encoding/csv"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the heficed parser
type Parser struct{}

// NewParser creates a new heficed parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from heficed.com
// Handles both regular abuse reports and CSV spam attachments
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	bodyLower := strings.ToLower(body)

	// Extract ticket information
	ticketID := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Ticket ID:", ""))
	status := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Status:", ""))
	priority := common.FindStringWithoutMarkers(body, "Priority:", "")

	externalCaseInfo := &events.ExternalCaseInformation{
		CaseID:   ticketID,
		Status:   status,
		Severity: priority,
	}

	// Check for CSV spam attachment (from abuse@heficed)
	fromAddr := ""
	if from, ok := serializedEmail.Headers["from"]; ok && len(from) > 0 {
		fromAddr = strings.ToLower(from[0])
	}

	if strings.Contains(bodyLower, "spam") && strings.Contains(fromAddr, "abuse@heficed") {
		return parseSpamCSV(serializedEmail, externalCaseInfo)
	}

	// Parse single event from body
	subject := common.FindStringWithoutMarkers(body, "Subject:", "")
	if subject == "" {
		subject, err = common.GetSubject(serializedEmail, true)
		if err != nil {
			return nil, err
		}
	}

	// Extract URL
	url := common.GetNonEmptyLineAfter(bodyLower, "following url")
	if !strings.Contains(url, "http") {
		url = ""
	}

	// Create event
	event := events.NewEvent("heficed")

	// Get event date from headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// The IP is in the subject
	event.IP = common.ExtractOneIP(subject)
	event.URL = url

	// Add external case information
	event.AddEventDetail(externalCaseInfo)

	// Determine event type
	if strings.Contains(bodyLower, "spam") {
		event.EventTypes = []events.EventType{events.NewSpam()}
	} else if strings.Contains(bodyLower, "phishing") {
		event.EventTypes = []events.EventType{events.NewPhishing()}
	} else if strings.Contains(bodyLower, "denial of service") || strings.Contains(bodyLower, "ddos") || strings.Contains(bodyLower, "flooded") {
		event.EventTypes = []events.EventType{events.NewDDoS()}
	} else if strings.Contains(bodyLower, "brute force scan") {
		event.EventTypes = []events.EventType{events.NewPortScan()}
	} else if strings.Contains(bodyLower, "trademark") {
		event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}
	} else if strings.Contains(bodyLower, "hacking attempt") {
		event.EventTypes = []events.EventType{events.NewWebHack()}
	} else if strings.Contains(subject, "[copyright") || strings.Contains(bodyLower, "copyright") {
		event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}
	} else if strings.Contains(bodyLower, "access attempt") {
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	} else if strings.Contains(subject, "[bot") || strings.Contains(bodyLower, "bot") {
		event.EventTypes = []events.EventType{events.NewBot("")}
	} else if strings.Contains(subject, "[ddos-amplification") || strings.Contains(bodyLower, "ddos-amplification") {
		event.EventTypes = []events.EventType{events.NewDDoS()}
	} else if strings.Contains(subject, "[fraud") || strings.Contains(bodyLower, "scam") {
		event.EventTypes = []events.EventType{events.NewFraud()}
	} else {
		return nil, common.NewNewTypeError("Unable to determine event type for heficed: " + subject)
	}

	return []*events.Event{event}, nil
}

// parseSpamCSV parses spam CSV attachments
func parseSpamCSV(serializedEmail *email.SerializedEmail, externalCaseInfo *events.ExternalCaseInformation) ([]*events.Event, error) {
	var eventsList []*events.Event
	seenIPs := make(map[string]bool)

	// Get CSV attachment from parts[1]
	if len(serializedEmail.Parts) < 2 {
		return nil, common.NewParserError("Expected CSV attachment in parts[1]")
	}

	csvBody := ""
	switch body := serializedEmail.Parts[1].Body.(type) {
	case string:
		csvBody = body
	case []byte:
		csvBody = string(body)
	default:
		return nil, common.NewParserError("Unexpected CSV body type")
	}

	// CSV can contain multiple sections separated by \n\n
	csvParts := strings.Split(csvBody, "\n\n")

	for _, csvPart := range csvParts {
		// Split by '# \n' to get the CSV data (skip comments)
		lines := strings.Split(csvPart, "#\n")
		if len(lines) == 0 {
			continue
		}

		csvData := lines[len(lines)-1] // Get last part (actual CSV data)

		// Parse CSV
		reader := csv.NewReader(strings.NewReader(csvData))
		reader.LazyQuotes = true
		records, err := reader.ReadAll()
		if err != nil || len(records) < 2 {
			continue
		}

		// Normalize headers
		headers := make([]string, len(records[0]))
		for i, h := range records[0] {
			headers[i] = strings.ToLower(strings.TrimSpace(h))
		}

		// Process each row
		for i := 1; i < len(records); i++ {
			entry := make(map[string]string)
			for j, value := range records[i] {
				if j < len(headers) {
					entry[headers[j]] = value
				}
			}

			ip := entry["ip"]
			if ip == "" || seenIPs[ip] {
				continue
			}
			seenIPs[ip] = true

			event := events.NewEvent("heficed")
			event.IP = ip
			event.EventDate = email.ParseDate(entry["time"])
			event.EventTypes = []events.EventType{events.NewSpam()}

			// Add external case information
			event.AddEventDetail(externalCaseInfo)

			// Add email details
			event.AddEventDetail(&events.Email{
				FromAddress: entry["from"],
				ToAddress:   entry["to"],
			})

			eventsList = append(eventsList, event)
		}
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("No events parsed from CSV")
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
