package dnsc

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
	bodyLower := strings.ToLower(body)

	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	event := events.NewEvent("dnsc")

	// Determine event type based on subject
	if strings.Contains(subjectLower, "fraud") {
		event.EventTypes = []events.EventType{events.NewFraud()}
	} else if strings.Contains(subjectLower, "cyber security incident") {
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
	} else {
		return nil, common.NewNewTypeError(subjectLower)
	}

	// Set event date from email headers
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Extract IP from subject (Python code sets ip = subject_lower, but likely meant to extract)
	event.IP = common.ExtractOneIP(subjectLower)

	// Extract URL from body between markers
	event.URL = common.FindStringWithoutMarkers(bodyLower, "details -------------------------", "---")

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
