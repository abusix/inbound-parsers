package orangecyberdefense

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
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Convert to lowercase for matching
	bodyLower := strings.ToLower(body)

	// Determine which parser to use based on body content
	if strings.Contains(bodyLower, "phishing") {
		return p.parsePhishing(serializedEmail, body)
	} else if strings.Contains(bodyLower, "trademark") {
		return p.parseTrademark(serializedEmail, body)
	}

	return nil, fmt.Errorf("unknown type: %s", subject)
}

func (p *Parser) parsePhishing(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	event := events.NewEvent("orangecyberdefense")

	// Set event date from email date header
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Create phishing event type with URLs
	phishing := events.NewPhishing()

	// Extract phishing_url (phishing_target in Go)
	phishingURL := common.FindStringWithoutMarkers(
		body,
		"redirects to a phishing page located at  ",
		"<",
	)
	if phishingURL != "" {
		phishing.PhishingTarget = phishingURL
	}

	// Extract official_url (nested find_string_without_markers)
	officialSection := common.FindStringWithoutMarkers(body, "We have verified that", ".<")
	if officialSection != "" {
		officialURL := common.FindStringWithoutMarkers(officialSection, "(", ")")
		if officialURL != "" {
			phishing.OfficialURL = officialURL
		}
	}

	event.EventTypes = []events.EventType{phishing}

	// Extract IP and URL
	// Try first method: check for "following URL and IP address:"
	eventLine := common.FindStringWithoutMarkers(body, "following URL and IP address:", "Target")
	if eventLine != "" {
		// Clean up defanged URLs
		eventLine = strings.ReplaceAll(eventLine, "[://]", "://")
		eventLine = strings.ReplaceAll(eventLine, "[.]", ".")
		event.IP = eventLine
		event.URL = eventLine
	} else {
		// Second method: parse from separate fields
		bodyModified := body
		bodyModified = strings.ReplaceAll(bodyModified, "IP address(es):", "IP:")
		bodyModified = strings.ReplaceAll(bodyModified, "IP address:", "IP:")
		bodyModified = strings.ReplaceAll(bodyModified, "<br />", "\n")

		event.URL = common.FindStringWithoutMarkers(bodyModified, "URL: ", "")
		ipValue := common.FindStringWithoutMarkers(bodyModified, "IP: ", "")
		if ipValue != "" {
			event.IP = strings.ReplaceAll(ipValue, "[.]", ".")
		}
	}

	return []*events.Event{event}, nil
}

func (p *Parser) parseTrademark(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	event := events.NewEvent("orangecyberdefense")

	// Create trademark event type
	trademark := events.NewTrademark("", nil, "", "")
	event.EventTypes = []events.EventType{trademark}

	// Set event date from email date header
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Extract URL
	event.URL = common.GetNonEmptyLineAfter(body, "at the following URL:")

	// Extract IP
	event.IP = common.FindStringWithoutMarkers(body, "IP", "")

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
