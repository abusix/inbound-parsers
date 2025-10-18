package ionos

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

// parseSpam handles spam reports
func parseSpam(body string, event *events.Event) []*events.Event {
	// Extract event date from 'start:' marker
	eventDateStr := strings.TrimSpace(common.FindStringWithoutMarkers(body, "start:", ""))
	if eventDateStr != "" {
		event.EventDate = email.ParseDate(eventDateStr)
	}

	// Set event type to spam
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Extract IP from 'sender_ip:' marker
	ipStr := strings.TrimSpace(common.FindStringWithoutMarkers(body, "sender_ip:", ""))
	if validIP := common.IsIP(ipStr); validIP != "" {
		event.IP = validIP
	}

	return []*events.Event{event}
}

// parsePhishing handles phishing site reports
func parsePhishing(body string, event *events.Event, dateHeader string) []*events.Event {
	// Use email date header
	if dateHeader != "" {
		event.EventDate = email.ParseDate(dateHeader)
	}

	// Set event type to phishing
	event.EventTypes = []events.EventType{events.NewPhishing()}

	// Extract IP from 'IP:' marker
	ipStr := strings.TrimSpace(common.FindStringWithoutMarkers(body, "IP:", ""))
	if validIP := common.IsIP(ipStr); validIP != "" {
		event.IP = validIP
	}

	// Extract URL from 'URL:' marker
	urlStr := strings.TrimSpace(common.FindStringWithoutMarkers(body, "URL:", ""))
	if urlStr != "" {
		event.URL = urlStr
	}

	return []*events.Event{event}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, _ := common.GetSubject(serializedEmail, false)

	// Create base event
	event := events.NewEvent("ionos")

	// Extract Case-ID and add as external ID
	caseID := common.FindStringWithoutMarkers(body, "Case-ID: [", "]")
	if caseID != "" {
		event.AddEventDetail(&events.ExternalID{ID: caseID})
	}

	// Determine event type and parse accordingly
	if strings.Contains(body, "sending phishing mails") {
		return parseSpam(body, event), nil
	} else if strings.Contains(subject, "Phishing site found") {
		// Get date from email headers
		dateHeader := ""
		if date, ok := serializedEmail.Headers["date"]; ok && len(date) > 0 {
			dateHeader = date[0]
		}
		return parsePhishing(body, event, dateHeader), nil
	}

	// Unknown type
	return nil, common.NewNewTypeError(subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
