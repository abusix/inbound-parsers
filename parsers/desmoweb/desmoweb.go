package desmoweb

import (
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
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("no email body found")
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil || subject == "" {
		return nil, common.NewParserError("no subject found")
	}

	subjectLower := strings.ToLower(subject)

	if strings.Contains(subjectLower, "scans") {
		event := events.NewEvent("desmoweb")

		// Extract event date from line after 'desmoWeb team'
		dateStr := common.GetNonEmptyLineAfter(body, "desmoWeb team")
		if dateStr != "" {
			parsedDate := email.ParseDate(dateStr)
			if parsedDate != nil {
				event.EventDate = parsedDate
			}
		}

		// Set IP to the subject (as per Python implementation)
		event.IP = subject

		event.EventTypes = []events.EventType{events.NewPortScan()}

		return []*events.Event{event}, nil
	}

	// Unknown subject type
	return nil, common.NewParserError("unknown email type: " + subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
