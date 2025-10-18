package terra

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
	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	// Check if subject contains "phishing"
	if strings.Contains(subjectLower, "phishing") {
		return parsePhishing(subject, serializedEmail)
	}

	// Unknown type
	return nil, common.NewNewTypeError(subject)
}

func parsePhishing(subject string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	event := events.NewEvent("terra")

	// Set event date from headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Set event types
	event.EventTypes = []events.EventType{events.NewPhishing()}

	// Extract IP from subject
	ip := common.IsIP(subject)
	if ip == "" {
		return nil, common.NewParserError("didn't find any IP in the subject")
	}
	event.IP = ip

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
