// Package neptus implements the Neptus parser for abuse reports
package neptus

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the Neptus parser
type Parser struct{}

// NewParser creates a new Neptus parser
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from monitoring@neptus.co.id
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	event := events.NewEvent("neptus")

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate := email.ParseDate(dateHeaders[0])
		event.EventDate = eventDate
	}

	// Try to find IP in body
	event.IP = common.FindStringWithoutMarkers(body, "Report Abuse Form IP", " we detected")

	// If not found in text body, try HTML attachment
	if event.IP == "" {
		bodyHTML, err := common.FindFirstAttachmentWithMimeType(serializedEmail, "html")
		if err == nil {
			// Strip HTML tags to get text
			bodyText := stripHTMLTags(bodyHTML)

			// Try get_non_empty_line_after first
			event.IP = common.GetNonEmptyLineAfter(bodyText, "Form IP")

			// Fallback to find_string_without_markers
			if event.IP == "" {
				event.IP = common.FindStringWithoutMarkers(bodyText, "Form IP", "")
			}
		}
	}

	// Determine event type based on body content
	bodyLower := strings.ToLower(body)

	if strings.Contains(bodyLower, "illegal resource access") ||
		strings.Contains(bodyLower, "illegeal resource access") ||
		strings.Contains(bodyLower, "cross-site scripting") ||
		strings.Contains(bodyLower, "cross site scripting") ||
		strings.Contains(bodyLower, "sql injection") {
		event.EventTypes = []events.EventType{events.NewWebHack()}
		return []*events.Event{event}, nil
	}

	if strings.Contains(body, "Bad Bot") {
		event.EventTypes = []events.EventType{events.NewBot("")}
		return []*events.Event{event}, nil
	}

	if strings.Contains(body, "DDoS") {
		event.EventTypes = []events.EventType{events.NewDDoS()}
		return []*events.Event{event}, nil
	}

	// Unknown type - raise error
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	return nil, common.NewNewTypeError(subject)
}

// stripHTMLTags removes HTML tags from a string and converts to plain text
func stripHTMLTags(html string) string {
	// Replace common block elements with newlines
	html = regexp.MustCompile(`(?i)<br[^>]*>`).ReplaceAllString(html, "\n")
	html = regexp.MustCompile(`(?i)<div[^>]*>`).ReplaceAllString(html, "\n")
	html = regexp.MustCompile(`(?i)<p[^>]*>`).ReplaceAllString(html, "\n")
	html = regexp.MustCompile(`(?i)</div>`).ReplaceAllString(html, "\n")
	html = regexp.MustCompile(`(?i)</p>`).ReplaceAllString(html, "\n")

	// Remove all remaining HTML tags
	html = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(html, "")

	// Clean up whitespace
	html = strings.TrimSpace(html)

	return html
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
