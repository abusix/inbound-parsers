package pj3cx

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

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Find HTML attachment and extract text
	bodyHTML, err := common.FindFirstAttachmentWithMimeType(serializedEmail, "html")
	if err != nil {
		return nil, common.NewParserError("HTML attachment not found")
	}

	// Extract text from HTML (simple tag removal)
	body := removeHTMLTags(bodyHTML)

	event := events.NewEvent("pj3cx")

	// Try to extract IP and date from body using regex
	// Pattern: "to report IP 1.2.3.4.* (on|today) (.*) PDT"
	pattern := regexp.MustCompile(`(?i)to report IP (\d+\.\d+\.\d+\.\d+).* (on|today) (.*) PDT`)
	if match := pattern.FindStringSubmatch(body); match != nil {
		// IP is in group 1, date is in group 3
		event.IP = match[1]
		dateStr := match[3]
		event.EventDate = email.ParseDate(dateStr)
	} else {
		// Fallback: use subject as IP and email date
		subject, _ := common.GetSubject(serializedEmail, false)
		event.IP = subject

		// Get date from email headers
		if serializedEmail.Headers != nil {
			if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
				event.EventDate = email.ParseDate(dateHeaders[0])
			}
		}
	}

	// Check for event type in body
	bodyLower := strings.ToLower(body)
	if strings.Contains(bodyLower, "malicious") {
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
	} else {
		return nil, common.NewParserError("unknown event type, adapt the parser")
	}

	return []*events.Event{event}, nil
}

// removeHTMLTags removes HTML tags from a string to extract plain text
func removeHTMLTags(html string) string {
	// Simple regex to remove HTML tags and extract text
	tagPattern := regexp.MustCompile(`<[^>]+>`)
	text := tagPattern.ReplaceAllString(html, " ")

	// Normalize whitespace
	spacePattern := regexp.MustCompile(`\s+`)
	text = spacePattern.ReplaceAllString(text, " ")

	return strings.TrimSpace(text)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
