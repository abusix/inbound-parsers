package opsec_protect

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
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)

	// Check if this is a trademark infringement
	if !strings.Contains(bodyLower, "trademark") {
		return nil, fmt.Errorf("new type: %s", subjectLower)
	}

	event := events.NewEvent("opsec_protect")

	// Set event date from email headers
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Set event type to Trademark
	event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}

	// Try to extract URL in order of preference
	if url := common.FindStringWithoutMarkers(bodyLower, "url:", ""); url != "" {
		event.URL = url
	} else if url := common.GetNonEmptyLineAfter(bodyLower, "following url(s)"); url != "" {
		event.URL = url
	} else {
		// Extract URL from subject between "infringement" and "["
		event.URL = common.FindStringWithoutMarkers(subjectLower, "infringement", "[")
	}

	// Try to extract IP (non-critical, ignore errors)
	if ip := common.FindStringWithoutMarkers(bodyLower, "ip:", ""); ip != "" {
		event.IP = ip
	}

	// Extract external ID from subject between "[" and "]"
	externalID := common.FindStringWithoutMarkers(subjectLower, "[", "]")
	if externalID != "" {
		event.AddEventDetail(&events.ExternalID{ID: externalID})
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
