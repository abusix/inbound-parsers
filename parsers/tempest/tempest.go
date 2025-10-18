package tempest

import (
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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Get event date from headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	subjectLower := strings.ToLower(subject)

	event := events.NewEvent("tempest")
	event.EventDate = eventDate

	// Check for trademark events
	if strings.Contains(subjectLower, "trademark") {
		event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}
		event.URL = common.FindStringWithoutMarkers(body, "of the website", ", which")
		return []*events.Event{event}, nil
	}

	// Check for phishing events
	if strings.Contains(subjectLower, "phishing") || strings.Contains(body, "phishing") {
		event.EventTypes = []events.EventType{events.NewPhishing()}
		event.IP = subjectLower
		event.URL = common.GetNonEmptyLineAfter(body, "web site which is hosted at:")
		return []*events.Event{event}, nil
	}

	// If we get here, it's an unknown type
	return nil, common.NewParserError("unknown event type in subject: " + subjectLower)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
