package klingler_net

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

var (
	targetPattern = regexp.MustCompile(`towards (?P<url>\S+)`)
	eventPattern  = regexp.MustCompile(`(?P<ip>(\d|\.)+) - - \[(?P<date>.*)\]`)
)

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)

	// Get date fallback from headers
	dateFallback := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateFallback = dateHeaders[0]
	}

	event := events.NewEvent("klingler_net")

	// Extract target URL from subject if present
	if targetMatch := targetPattern.FindStringSubmatch(subject); len(targetMatch) > 0 {
		targetURL := targetMatch[1]
		if !strings.HasPrefix(targetURL, "http") {
			targetURL = "http://" + targetURL
		}
		event.AddEventDetail(&events.Target{URL: targetURL})
	}

	// Try to extract IP and date from body
	if eventMatch := eventPattern.FindStringSubmatch(body); len(eventMatch) > 0 {
		event.IP = eventMatch[1]
		// Try to parse the date from the log entry
		dateStr := eventMatch[3]
		parsedDate := email.ParseDate(dateStr)
		if parsedDate != nil {
			event.EventDate = parsedDate
		} else {
			// Fall back to email date header
			event.EventDate = email.ParseDate(dateFallback)
		}
	} else {
		// If pattern doesn't match, use subject as IP and fallback date
		event.IP = subjectLower
		event.EventDate = email.ParseDate(dateFallback)
	}

	// Determine event type based on subject content
	if strings.Contains(subjectLower, "mail form attacks") {
		event.EventTypes = []events.EventType{events.NewSpam()}
		return []*events.Event{event}, nil
	} else if strings.Contains(subjectLower, "attack") || strings.Contains(subjectLower, "attacken") {
		event.EventTypes = []events.EventType{events.NewWebHack()}
		// Extract target IP from body
		targetIP := common.FindStringWithoutMarkers(body, "towards", ":")
		if targetIP != "" {
			event.AddEventDetail(&events.Target{IP: targetIP})
		}
		return []*events.Event{event}, nil
	}

	return nil, common.NewNewTypeError(subjectLower)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
