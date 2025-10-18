package bp_corsearch

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
	// Get body and replace &nbsp; with spaces (matching Python behavior)
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	body = strings.ReplaceAll(body, "&nbsp;", " ")

	// Create event with Trademark type
	event := events.NewEvent("bp_corsearch")
	event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}

	// Set event date from email headers
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Extract URL between "located at:" and "We have"
	url := common.FindStringWithoutMarkers(body, "located at:", "We have")
	if url != "" {
		event.URL = strings.TrimSpace(url)
	}

	// Extract IP between "Notice" and "Dear"
	ip := common.FindStringWithoutMarkers(body, "Notice", "Dear")
	if ip != "" {
		event.IP = strings.TrimSpace(ip)
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
