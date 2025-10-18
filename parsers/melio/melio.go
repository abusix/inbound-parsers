package melio

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

	// Check if body contains 'malicious' (case-insensitive)
	if strings.Contains(strings.ToLower(body), "malicious") {
		return parseMalicious(subject, serializedEmail)
	}

	return nil, common.NewNewTypeError(subject)
}

func parseMalicious(subject string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	event := events.NewEvent("melio")

	// Get event date from headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}
	event.EventDate = eventDate

	// Set event type
	event.EventTypes = []events.EventType{events.NewMaliciousActivity()}

	// Try to set IP from subject
	// The subject should contain the IP address
	event.IP = strings.TrimSpace(subject)

	// Validate that we got something that looks like an IP
	if event.IP == "" {
		return nil, common.NewParserError("Couldn't get IP")
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
