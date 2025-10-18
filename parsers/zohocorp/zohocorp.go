package zohocorp

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
	// Get From address for matching logic
	fromAddr, err := common.GetFrom(serializedEmail, false)
	if err != nil {
		return nil, common.NewIgnoreError("no from address")
	}

	// Match: check if from_addr contains '@zohocorp.com'
	if !strings.Contains(fromAddr, "@zohocorp.com") {
		return nil, common.NewIgnoreError("not from zohocorp.com")
	}

	// Get subject
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Check for "re:" in subject (case-insensitive) - should reject
	if strings.Contains(strings.ToLower(subject), "re:") {
		return nil, common.NewRejectError("subject contains 're:'")
	}

	// Get body
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Create event
	event := events.NewEvent("zohocorp")

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Check subject for event type
	subjectLower := strings.ToLower(subject)
	if strings.Contains(subjectLower, "phishing") {
		event.EventTypes = []events.EventType{events.NewPhishing()}

		// Extract URL: find_string_without_markers(body, 'Received: from', '(')
		event.URL = common.FindStringWithoutMarkers(body, "Received: from", "(")

		// Extract IP: find_string_without_markers(body, '([', '])')
		event.IP = common.FindStringWithoutMarkers(body, "([", "])")

		return []*events.Event{event}, nil
	}

	// Unknown type in subject
	return nil, common.NewNewTypeError(subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
