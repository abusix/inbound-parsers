package mxtoolbox

import (
	"fmt"
	"strings"

	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get body: %w", err)
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get subject: %w", err)
	}

	// Check if this is an "Added to" notification
	if !strings.Contains(subject, "Added to") {
		return nil, fmt.Errorf("unsupported mxtoolbox email type: %s", subject)
	}

	event := events.NewEvent("mxtoolbox")

	// Extract the blacklist name from the body
	listName := common.FindStringWithoutMarkers(body, "Added to ", "")
	event.EventTypes = []events.EventType{events.NewBlacklist(listName)}

	// The subject contains the IP address
	event.IP = subject

	// Get the event date from the email headers
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
