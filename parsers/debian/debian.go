package debian

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
	// Get from address to determine parsing logic
	fromAddr := ""
	if from, ok := serializedEmail.Headers["from"]; ok && len(from) > 0 {
		fromAddr = strings.ToLower(from[0])
	}

	// Get body and subject
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	// Create base event
	event := events.NewEvent("debian")

	// Set event date from email headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		event.EventDate = email.ParseDate(dateHeader[0])
	}

	// Route to appropriate parser based on from address
	// Python uses exact equality checks (line 45, 47)
	if fromAddr == "93sam@debian.org" {
		return parse93sam(subject, body, event)
	}

	if fromAddr == "rak@debian.org" || fromAddr == "adsb@debian.org" {
		return parseSubject(subject, event)
	}

	// Unknown from address
	return nil, common.NewNewTypeError(fromAddr)
}

func parse93sam(subject, body string, event *events.Event) ([]*events.Event, error) {
	bodyLower := strings.ToLower(body)

	// Determine event type based on body content
	if strings.Contains(bodyLower, "phishing") {
		event.EventTypes = []events.EventType{events.NewPhishing()}
	} else if strings.Contains(bodyLower, "spam") {
		event.EventTypes = []events.EventType{events.NewSpam()}
	} else {
		return nil, common.NewNewTypeError(subject)
	}

	// Extract IP address - matches Python logic
	ip := common.FindStringWithoutMarkers(body, "Received:", ")")
	if ip == "" {
		ip = common.FindStringWithoutMarkers(body, "host:", "")
	}

	// Set IP directly as extracted (Python doesn't do further extraction)
	event.IP = ip

	return []*events.Event{event}, nil
}

func parseSubject(subject string, event *events.Event) ([]*events.Event, error) {
	subjectLower := strings.ToLower(subject)

	if strings.Contains(subjectLower, "spam") {
		event.EventTypes = []events.EventType{events.NewSpam()}
	} else {
		return nil, common.NewNewTypeError(subject)
	}

	// Set IP to the entire subject line (as per Python implementation line 36)
	// Python directly assigns: event.ip = subject
	event.IP = subject

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
