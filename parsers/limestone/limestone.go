// Package limestone implements the parser for Limestone Networks abuse reports
package limestone

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the Limestone Networks parser
type Parser struct{}

// NewParser creates a new Limestone parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from Limestone Networks
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get body and subject with throws=true
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Strip HTML tags from body and normalize whitespace
	body = stripHTMLTags(body)
	body = strings.ReplaceAll(body, "\r\n", " ")

	subjectLower := strings.ToLower(subject)

	// Extract status and ticket number from body
	status := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Status:", ""))
	ticket := common.FindStringWithoutMarkers(body, "Ticket #", "")

	// Create event
	event := events.NewEvent("limestone")

	// Determine event type based on subject/body content
	if strings.Contains(subjectLower, "spam") {
		event.EventTypes = []events.EventType{events.NewSpam()}
	} else if strings.Contains(body, "exploited server") {
		event.EventTypes = []events.EventType{events.NewCompromisedServer()}
	} else {
		return nil, common.NewNewTypeError(subjectLower)
	}

	// Extract IP from subject
	// Note: Python code has bug where it sets event.ip = subject_lower
	// We'll extract the actual IP instead
	ipAddress := common.ExtractOneIP(subjectLower)
	if ipAddress != "" {
		event.IP = ipAddress
	}

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate := email.ParseDate(dateHeaders[0])
		event.EventDate = eventDate
	}

	// Add external case information
	event.AddEventDetail(&events.ExternalCaseInformation{
		CaseID: ticket,
		Status: status,
	})

	return []*events.Event{event}, nil
}

// stripHTMLTags removes HTML tags from a string (similar to BeautifulSoup text extraction)
func stripHTMLTags(html string) string {
	// Simple regex to remove HTML tags
	tagRegex := regexp.MustCompile(`<[^>]*>`)
	text := tagRegex.ReplaceAllString(html, "")

	// Decode common HTML entities
	text = strings.ReplaceAll(text, "&nbsp;", " ")
	text = strings.ReplaceAll(text, "&amp;", "&")
	text = strings.ReplaceAll(text, "&lt;", "<")
	text = strings.ReplaceAll(text, "&gt;", ">")
	text = strings.ReplaceAll(text, "&quot;", "\"")
	text = strings.ReplaceAll(text, "&#39;", "'")

	return text
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
