// Package perfettivanmelle implements the perfettivanmelle.com parser
package perfettivanmelle

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the perfettivanmelle parser
type Parser struct{}

var (
	materialPattern = regexp.MustCompile(`(?i)our rights in the trademark (?P<material>\w+)(:|\.)`)
	urlPattern      = regexp.MustCompile(`<(?P<url>.*)>$`)
)

// Parse parses emails from @perfettivanmelle.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	bodyLower := strings.ToLower(body)

	// Get date from headers
	dateFallback := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateFallback = dateHeaders[0]
	}

	// Extract trademarked material from body
	var trademarkedMaterial string
	if match := materialPattern.FindStringSubmatch(bodyLower); len(match) > 1 {
		trademarkedMaterial = match[1]
	} else {
		return nil, common.NewNewTypeError("perfettivanmelle: trademark material not found")
	}

	// Extract URL block
	urlBlock := common.FindStringWithoutMarkers(
		strings.ReplaceAll(bodyLower, "websites", "website"),
		"you are hosting the website for",
		"which",
	)

	if urlBlock == "" {
		return nil, common.NewParserError("perfettivanmelle: URL block not found")
	}

	// Parse URLs from block
	var eventsList []*events.Event
	lines := strings.Split(urlBlock, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		event := events.NewEvent("perfettivanmelle")

		// Set event date
		eventDate := email.ParseDate(dateFallback)
		event.EventDate = eventDate

		// Set event type with trademarked material
		event.EventTypes = []events.EventType{
			events.NewTrademark("", nil, "", trademarkedMaterial),
		}

		// Extract URL from angle brackets if present
		url := line
		if urlMatch := urlPattern.FindStringSubmatch(line); len(urlMatch) > 1 {
			url = urlMatch[1]
		}

		event.URL = url
		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("perfettivanmelle: no URLs found")
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
