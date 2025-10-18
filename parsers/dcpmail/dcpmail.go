// Package dcpmail implements the DCP Mail parser
package dcpmail

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the dcpmail parser
type Parser struct{}

// NewParser creates a new dcpmail parser instance
func NewParser() *Parser {
	return &Parser{}
}

// stripHTML removes HTML tags from a string, similar to BeautifulSoup's .strings
func stripHTML(html string) string {
	// Remove HTML tags
	re := regexp.MustCompile(`<[^>]*>`)
	text := re.ReplaceAllString(html, "\n")

	// Normalize whitespace
	text = regexp.MustCompile(`[ \t]+`).ReplaceAllString(text, " ")

	// Remove multiple empty lines
	lines := strings.Split(text, "\n")
	var result []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && trimmed != " " {
			result = append(result, trimmed)
		}
	}

	return strings.Join(result, "\n")
}

// parseHTMLTable parses the HTML table format for Sky Italia emails
func parseHTMLTable(body string, eventTemplate *events.Event) ([]*events.Event, error) {
	// Parse the HTML body similar to BeautifulSoup
	parsedBody := stripHTML(body)

	// Extract IP address
	ip := common.FindStringWithoutMarkers(parsedBody, "from the IP ", ",")

	// Extract the content section
	contentStart := "Incident ID\nURL\nDate seen (UTC)\n"
	contentEnd := "Sky Italia"

	if !strings.Contains(parsedBody, contentStart) {
		return nil, common.NewParserError("content not found")
	}

	parts := strings.Split(parsedBody, contentStart)
	if len(parts) < 2 {
		return nil, common.NewParserError("content not found")
	}

	contentSection := parts[1]
	if idx := strings.Index(contentSection, contentEnd); idx != -1 {
		contentSection = contentSection[:idx]
	}

	// Split into lines and parse triplets (incident_id, url, date)
	lines := strings.Split(strings.TrimSpace(contentSection), "\n")
	var incidents, urls, dates []string

	for i := 0; i < len(lines); i += 3 {
		if i < len(lines) {
			incidents = append(incidents, strings.TrimSpace(lines[i]))
		}
		if i+1 < len(lines) {
			urls = append(urls, strings.TrimSpace(lines[i+1]))
		}
		if i+2 < len(lines) {
			dates = append(dates, strings.TrimSpace(lines[i+2]))
		}
	}

	// Create events
	var result []*events.Event
	maxLen := len(incidents)
	if len(urls) < maxLen {
		maxLen = len(urls)
	}
	if len(dates) < maxLen {
		maxLen = len(dates)
	}

	for i := 0; i < maxLen; i++ {
		if strings.HasPrefix(urls[i], "http") {
			// Create a copy of the event template
			event := events.NewEvent(eventTemplate.Parser)
			event.EventTypes = eventTemplate.EventTypes
			event.URL = urls[i]
			event.IP = ip

			// Parse the date
			eventDate := email.ParseDate(dates[i])
			event.EventDate = eventDate

			// Add external ID
			event.AddEventDetail(&events.ExternalID{ID: incidents[i]})

			result = append(result, event)
		}
	}

	return result, nil
}

// Parse parses emails from @dcpmail
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)

	// Create base event
	event := events.NewEvent("dcpmail")

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate := email.ParseDate(dateHeaders[0])
		event.EventDate = eventDate
	}

	// Extract owner from "our Client, <owner> ("
	owner := common.FindStringWithoutMarkers(body, "our Client,", "(")
	if owner != "" {
		// Split by comma and take the first part
		parts := strings.Split(owner, ",")
		if len(parts) > 0 {
			owner = strings.TrimSpace(parts[0])
		}
	}

	// Determine event type based on subject and body
	if strings.Contains(subjectLower, "trademark") || strings.Contains(bodyLower, "trademark") {
		event.EventTypes = []events.EventType{events.NewTrademark("", nil, owner, "")}
	} else if strings.Contains(subjectLower, "copyright") || strings.Contains(bodyLower, "copyright") {
		event.EventTypes = []events.EventType{events.NewCopyright("", owner, "")}
	} else {
		return nil, common.NewNewTypeError(subjectLower)
	}

	// Check if this is a Sky Italia HTML table format
	if strings.Contains(subjectLower, "sky italia") {
		return parseHTMLTable(body, event)
	}

	// Parse standard format
	externalID := common.FindStringWithoutMarkers(body, "Notice Reference:", "")
	externalID = strings.TrimSpace(externalID)

	url := common.FindStringWithoutMarkers(body, "Site:", "")
	url = strings.TrimSpace(url)

	ip := common.FindStringWithoutMarkers(body, "IP:", "")
	ip = strings.TrimSpace(ip)

	event.URL = url
	event.IP = ip

	if externalID != "" {
		event.AddEventDetail(&events.ExternalID{ID: externalID})
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
