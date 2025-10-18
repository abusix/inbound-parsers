// Package thomsentrampedach implements the Thomsen Trampedach Legal parser
// Handles phishing and trademark infringement reports from abuse@thomsentrampedach.legal
package thomsentrampedach

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the Thomsen Trampedach Legal parser
type Parser struct{}

// NewParser creates a new Thomsen Trampedach Legal parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from abuse@thomsentrampedach.legal
// Handles three types of reports:
// 1. "phishing page" in subject - reports phishing URLs, may include IP if "pointing to" appears
// 2. "phishing email" in subject - reports phishing IPs extracted from body
// 3. "trademark" in subject - reports trademark infringement URLs
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get body and subject with error handling
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)

	// Create base event
	event := events.NewEvent("thomsentrampedach")

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate := email.ParseDate(dateHeaders[0])
		event.EventDate = eventDate
	}

	// Determine event type and extract relevant data based on subject
	if strings.Contains(subjectLower, "phishing page") {
		// Phishing page report - extract URL from subject
		event.EventTypes = []events.EventType{events.NewPhishing()}

		// Extract URL from subject
		event.URL = extractURL(subject)

		// If "pointing to" is in subject, also extract IP
		if strings.Contains(subjectLower, "pointing to") {
			if ip := common.ExtractOneIP(subject); ip != "" {
				event.IP = ip
			}
		}

		return []*events.Event{event}, nil
	}

	if strings.Contains(subjectLower, "phishing email") {
		// Phishing email report - extract IP from body
		event.EventTypes = []events.EventType{events.NewPhishing()}

		// Extract IP from body after "IP" marker
		ipStr := common.FindStringWithoutMarkers(body, "IP", "")
		if ip := common.ExtractOneIP(ipStr); ip != "" {
			event.IP = ip
		}

		return []*events.Event{event}, nil
	}

	if strings.Contains(subjectLower, "trademark") {
		// Trademark infringement report - extract URL from subject
		event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}

		// Extract URL from subject
		event.URL = extractURL(subject)

		return []*events.Event{event}, nil
	}

	// Unknown report type
	return nil, common.NewNewTypeError(subject)
}

// extractURL attempts to extract a URL from text
// Returns the cleaned URL or the original text if no clear URL pattern is found
func extractURL(text string) string {
	// Clean common obfuscations
	cleaned := common.CleanURL(text)

	// Look for http:// or https:// patterns
	if strings.Contains(cleaned, "http://") || strings.Contains(cleaned, "https://") {
		// Extract the URL portion
		startIdx := strings.Index(cleaned, "http")
		if startIdx != -1 {
			urlPart := cleaned[startIdx:]

			// Find the end of the URL (space, newline, or end of string)
			for i, ch := range urlPart {
				if ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t' {
					return urlPart[:i]
				}
			}
			return urlPart
		}
	}

	// If no clear URL pattern, return the cleaned text
	// The subject itself might be the URL
	return cleaned
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
