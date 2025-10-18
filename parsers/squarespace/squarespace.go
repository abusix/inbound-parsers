// Package squarespace implements the Squarespace parser for abuse reports
package squarespace

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the Squarespace parser
type Parser struct{}

// Parse parses emails from @squarespace.com
// Handles phishing, deceptive site/domain, and webshell reports
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get subject and body - both are required
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)
	event := events.NewEvent("squarespace")

	// Determine event type based on subject
	if strings.Contains(subjectLower, "phish") {
		event.EventTypes = []events.EventType{events.NewPhishing()}
	} else if strings.Contains(subjectLower, "deceptive site/domain") {
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
	} else if strings.Contains(subjectLower, "webshell") {
		event.EventTypes = []events.EventType{events.NewWebHack()}
	} else {
		return nil, common.NewNewTypeError(subject)
	}

	// Get event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Extract case ID from body if present
	caseIDRegex := regexp.MustCompile(`(?i)case (\d+)`)
	if match := caseIDRegex.FindStringSubmatch(body); len(match) > 1 {
		event.AddEventDetail(&events.ExternalID{ID: match[1]})
	}

	// Try to extract IP from subject first, then fall back to URL
	ipAddr := common.ExtractOneIP(subject)
	if ipAddr != "" {
		event.IP = ipAddr
	} else {
		// Try to parse as URL
		processedURL, err := common.ProcessURL(subject)
		if err == nil && processedURL != "" {
			event.URL = processedURL
		}
	}

	// Validate that we found either IP or URL
	if event.IP == "" && event.URL == "" {
		return nil, common.NewParserError("No IP or URL were found")
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
