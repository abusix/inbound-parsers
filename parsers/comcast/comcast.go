package comcast

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
	// Get subject
	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil || subject == "" {
		return nil, err
	}

	// Create event
	event := events.NewEvent("comcast")

	// Determine event type based on subject
	subjectLower := strings.ToLower(subject)
	if strings.Contains(subjectLower, "spamming") {
		event.EventTypes = []events.EventType{events.NewSpam()}
	} else if strings.Contains(subjectLower, "phishing") {
		event.EventTypes = []events.EventType{events.NewPhishing()}
	} else {
		// Unknown type - return NewTypeError
		return nil, common.NewNewTypeError(subject)
	}

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Try to extract IP from subject: "customer at [IP]"
	if ip := common.FindStringWithoutMarkers(subject, "customer at [", "]"); ip != "" {
		event.IP = ip
	} else {
		// Try to extract URL: "customer URL is "
		if url := common.FindStringWithoutMarkers(subject, "customer", "is "); url != "" {
			event.URL = strings.TrimSpace(url)
		}
		// Try to extract IP from parentheses: "(IP)"
		if ip := common.FindStringWithoutMarkers(subject, "(", ")"); ip != "" {
			event.IP = ip
		}
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
