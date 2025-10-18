package buerki

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
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject = strings.ToLower(subject)

	// Check if subject contains "spam from"
	if !strings.Contains(subject, "spam from") {
		return nil, common.NewNewTypeError(subject)
	}

	// Create event
	event := events.NewEvent("buerki")
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Set event date from email header
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		event.EventDate = email.ParseDate(dateHeader[0])
	}

	// Extract IP from subject
	ip := common.ExtractOneIP(subject)
	if ip == "" {
		return nil, common.NewParserError("Couldn't find IP")
	}

	event.IP = ip

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
