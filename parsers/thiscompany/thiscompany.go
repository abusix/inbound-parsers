package thiscompany

import (
	"fmt"
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
		return nil, fmt.Errorf("failed to get email body: %w", err)
	}

	event := events.NewEvent("thiscompany")

	// Extract infringement type to determine event type
	eventType := common.FindStringWithoutMarkers(body, "Infringement type:", "")
	if eventType == "" {
		return nil, fmt.Errorf("could not find infringement type in email body")
	}

	// Check for Counterfeit or Trademark infringement
	if strings.Contains(eventType, "Counterfeit") || strings.Contains(eventType, "Trademark infringement") {
		event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}
	} else if strings.Contains(eventType, "Copyright") {
		event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}
	} else {
		return nil, fmt.Errorf("unknown event type: %s", eventType)
	}

	// Extract event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		// Store the raw date string - let downstream processing handle parsing
		event.Headers["date"] = dateHeaders[0]
	}

	// Extract IP address
	event.IP = common.FindStringWithoutMarkers(body, "IP address:", "")

	// Extract URL(s)
	event.URL = common.GetNonEmptyLineAfter(body, "URL(s) where illegal content is located:")

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
