package artplanet

import (
	"fmt"
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

// stripHTML removes HTML tags from a string (simple implementation matching BeautifulSoup.text behavior)
func stripHTML(html string) string {
	// Remove HTML tags
	re := regexp.MustCompile(`<[^>]*>`)
	text := re.ReplaceAllString(html, " ")

	// Clean up whitespace
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")
	return strings.TrimSpace(text)
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get body: %w", err)
	}

	// Strip HTML tags to get plain text (matching BeautifulSoup.text behavior)
	bodyText := stripHTML(body)

	// Extract IP, date, and target using regex
	// Pattern: "ip address (.*) at (.*) on our client (.*)\."
	re := regexp.MustCompile(`(?i)ip address (.*?) at (.*?) on our client (.*?)\.`)
	matches := re.FindStringSubmatch(strings.ToLower(bodyText))

	if matches == nil || len(matches) < 4 {
		return nil, fmt.Errorf("adapt the regex")
	}

	ip := strings.TrimSpace(matches[1])
	date := strings.TrimSpace(matches[2])
	target := strings.TrimSpace(matches[3])

	// Check if "ddos" is mentioned in the body
	if !strings.Contains(strings.ToLower(bodyText), "ddos") {
		subject, _ := common.GetSubject(serializedEmail, false)
		return nil, fmt.Errorf("new type error: %s", subject)
	}

	// Create event
	event := events.NewEvent("artplanet")
	event.IP = ip

	// Try to parse the date, but don't fail if it can't be parsed
	// The date from the body text may not be in RFC 5322 format
	if parsedDate := email.ParseDate(date); parsedDate != nil {
		event.EventDate = parsedDate
	} else {
		// Store raw date string in headers if parsing fails
		event.Headers["event_date_raw"] = date
	}

	event.EventTypes = []events.EventType{events.NewDDoS()}

	// Add target detail
	event.AddEventDetail(&events.Target{IP: target})

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
