// Package tikaj implements the tikaj parser for phishing and copyright reports
package tikaj

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the tikaj parser
type Parser struct{}

// NewParser creates a new tikaj parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from system@soc.tikaj.com
// Handles both phishing and copyright reports
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Replace <br /> with paragraph breaks for parsing
	body = strings.ReplaceAll(body, "<br />", "</p><p>")

	// Create base event
	event := events.NewEvent("tikaj")

	// Set event date from email date header
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate := email.ParseDate(dateHeaders[0])
		event.EventDate = eventDate
	}

	// Extract external ID from subject (after last |)
	externalID := ""
	if idx := strings.LastIndex(subject, "|"); idx != -1 {
		externalID = strings.TrimSpace(subject[idx+1:])
	}
	if externalID != "" {
		event.AddEventDetail(&events.ExternalID{ID: externalID})
	}

	// Determine event type based on body content
	bodyLower := strings.ToLower(body)

	if strings.Contains(bodyLower, "phishing") {
		return parsePhishing(event, body)
	} else if strings.Contains(bodyLower, "copyright") {
		return parseCopyright(event, body)
	}

	return nil, common.NewNewTypeError(subject)
}

// parsePhishing parses phishing reports from tikaj
func parsePhishing(event *events.Event, body string) ([]*events.Event, error) {
	event.EventTypes = []events.EventType{events.NewPhishing()}

	// Extract URL between 'below as evidence:</p><p>' and '</p><p>'
	url := common.FindStringWithoutMarkers(body, "below as evidence:</p><p>", "</p><p>")

	// Clean URL by replacing obfuscation patterns
	url = strings.ReplaceAll(url, "[:]", ":")
	url = strings.ReplaceAll(url, "[.]", ".")
	url = strings.TrimSpace(url)

	if url == "" {
		return nil, common.NewParserError("No URL found in tikaj phishing report")
	}

	event.URL = url

	return []*events.Event{event}, nil
}

// parseCopyright parses copyright reports from tikaj
func parseCopyright(event *events.Event, body string) ([]*events.Event, error) {
	event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}

	// Extract URL between 'the following URL (' and ')'
	url := common.FindStringWithoutMarkers(body, "the following URL (", ")")

	if url == "" {
		return nil, common.NewParserError("No URL found in tikaj copyright report")
	}

	event.URL = url

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
