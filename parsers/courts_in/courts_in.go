package courts_in

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

	// Check if this is the expected "Excessive HTTP requests" type
	if !strings.Contains(body, "Excessive HTTP requests in an allotted period of time") {
		return nil, common.NewNewTypeError(subject)
	}

	event := events.NewEvent("courts_in")
	event.EventTypes = []events.EventType{events.NewMaliciousActivity()}

	// Extract event date after "Date:" marker
	eventDateStr := common.GetNonEmptyLineAfter(body, "Date:")
	if eventDateStr != "" {
		event.EventDate = email.ParseDate(eventDateStr)
	}

	// Extract IP address after "IP Address:" marker
	event.IP = common.GetNonEmptyLineAfter(body, "IP Address:")

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
