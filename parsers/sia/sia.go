package sia

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser handles SIA phishing reports
type Parser struct{}

// NewParser creates a new SIA parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Match determines if this parser should handle the email
func (p *Parser) Match(serializedEmail *email.SerializedEmail) bool {
	fromAddr, err := common.GetFrom(serializedEmail, false)
	if err != nil {
		return false
	}

	return strings.Contains(fromAddr, "siacert@sia.es") ||
		strings.Contains(fromAddr, "alert@services.sia.es")
}

// Parse extracts phishing URLs from SIA email reports
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get email body
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Get subject
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Split body at <html> tag to get text portion only
	bodyParts := strings.Split(body, "<html>")
	textBody := bodyParts[0]

	// Check if this is a phishing report
	if !strings.Contains(strings.ToLower(subject), "phishing") {
		return nil, fmt.Errorf("no event created")
	}

	// Parse phishing URLs
	return parsePhishing(textBody, serializedEmail)
}

// parsePhishing extracts phishing URLs from the email body
func parsePhishing(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	var eventList []*events.Event

	// Find all obfuscated URLs (hxxp.*)
	urlPattern := regexp.MustCompile(`hxxp[^\s]*`)
	urls := urlPattern.FindAllString(strings.ToLower(body), -1)

	// Get event date from email headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	// Create an event for each URL found
	for _, url := range urls {
		// De-obfuscate URL
		url = strings.ReplaceAll(url, "hxxp", "http")

		event := events.NewEvent("sia")
		event.URL = url
		event.EventDate = eventDate
		event.EventTypes = []events.EventType{events.NewPhishing()}

		eventList = append(eventList, event)
	}

	if len(eventList) == 0 {
		return nil, fmt.Errorf("no phishing URLs found")
	}

	return eventList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
