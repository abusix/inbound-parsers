package oppl

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
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)
	if !strings.Contains(subjectLower, "spam") && !strings.Contains(subjectLower, "scam") {
		return nil, common.NewNewTypeError(subject)
	}

	event := events.NewEvent("oppl")

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate := email.ParseDate(dateHeaders[0])
		event.EventDate = eventDate
	}

	// Set event type
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Extract IP from body using "from ip" marker
	bodyLower := strings.ToLower(body)
	ip := common.FindStringWithoutMarkers(bodyLower, "from ip", "")
	event.IP = ip

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
