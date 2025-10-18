package octopusdns

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

	// Check if 'spam' is in subject
	if !strings.Contains(subjectLower, "spam") {
		return nil, common.NewNewTypeError(subjectLower)
	}

	// Extract IP using FindStringWithoutMarkers (searches for "ip" and extracts until line break)
	ip := common.FindStringWithoutMarkers(bodyLower, "ip", "")

	// Create event
	event := events.NewEvent("octopusdns")
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Set event date from headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Set IP address
	event.IP = ip

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
