package irisio

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
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	bodyLower := strings.ToLower(body)

	// Check if the body contains the expected pattern
	if strings.Contains(bodyLower, "scans/sql injection/spam posts/ddos") {
		event := events.NewEvent("irisio")

		// Set event date from headers
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}

		// Set event types
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}

		// Set IP from subject
		event.IP = subject

		return []*events.Event{event}, nil
	}

	// Unknown type - return NewTypeError
	return nil, common.NewNewTypeError(subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
