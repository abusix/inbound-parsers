package deft

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

	event := events.NewEvent("deft")

	// Parse event date from headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Determine event type based on subject
	subjectLower := strings.ToLower(subject)
	if strings.Contains(subjectLower, "port-scan") {
		event.EventTypes = []events.EventType{events.NewPortScan()}
	} else if strings.Contains(subjectLower, "ddos") {
		event.EventTypes = []events.EventType{events.NewDDoS()}
	} else {
		// Unknown type - return error
		return nil, common.NewNewTypeError(subject)
	}

	// Extract IP address from body
	event.IP = common.FindStringWithoutMarkers(body, "Reported IP:", "")

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
