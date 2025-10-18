package ufrgs

import (
	"fmt"
	"strings"

	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, _ := common.GetSubject(serializedEmail, false)
	body, _ := common.GetBody(serializedEmail, false)

	// Check if this is a login attempt report
	if !strings.Contains(strings.ToLower(body), "login attempt") {
		return nil, fmt.Errorf("NewTypeError: %s", subject)
	}

	// Create event
	event := events.NewEvent("ufrgs")

	// Set event types to LoginAttack
	event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

	// Set IP address from subject
	event.IP = strings.TrimSpace(subject)

	// Set event date from email headers
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			dateStr := dateHeaders[0]
			if parsedDate := email.ParseDate(dateStr); parsedDate != nil {
				event.EventDate = parsedDate
			}
		}
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
