package nt_gov

import (
	"regexp"
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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)

	event := events.NewEvent("nt_gov")
	event.EventTypes = []events.EventType{events.NewFraud()}

	// Parse event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	// Extract URL from body using regex pattern: name: <url>
	urlRegex := regexp.MustCompile(`name:\s+(\S+)`)
	if match := urlRegex.FindStringSubmatch(bodyLower); len(match) > 1 {
		event.URL = match[1]
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
