package valentinobrandprotection

import (
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// getURLBlock extracts URLs from a specific block of text in the email body
func getURLBlock(body string) []string {
	var urls []string

	// Find the block between "refer to the following url" and "we have tried to"
	block := common.FindStringWithoutMarkers(
		strings.ToLower(body),
		"refer to the following url",
		"we have tried to",
	)

	if block == "" {
		return urls
	}

	// Process each line in the block
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(line)
		if common.IsURL(line) {
			urls = append(urls, line)
		}
	}

	return urls
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get body - required
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Get subject - required
	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		subject = ""
	}

	// Validate subject contains expected text
	if !strings.Contains(strings.ToLower(subject), "notice of infringement") {
		return nil, common.NewNewTypeError(subject)
	}

	// Validate body contains expected text
	if !strings.Contains(strings.ToLower(body), "offers one or more counterfeit items") {
		return nil, common.NewNewTypeError("format changed adapt the parser")
	}

	// Extract ECIN from subject - format: "... word word word word ECIN:[12345] ..."
	// Split by space and get 5th element (index 4), then extract ECIN value
	subjectParts := strings.Fields(subject)
	if len(subjectParts) < 5 {
		return nil, common.NewParserError("subject format unexpected - cannot extract ECIN")
	}

	// Get the ECIN field and remove "ECIN:", "[", and "]"
	ecin := subjectParts[4]
	ecin = strings.ReplaceAll(ecin, "ECIN:", "")
	ecin = strings.Trim(ecin, "[]")

	// Extract IP address
	ip := common.FindStringWithoutMarkers(body, "IP:", "")
	ip = strings.TrimSpace(ip)

	// Extract URLs from the designated block
	urlBlock := getURLBlock(body)

	// Get event date from email headers
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	// Create event type - Trademark with owner "VALENTINO S.P.A."
	eventType := &events.Trademark{
		BaseEventType: events.BaseEventType{
			Name: "trademark",
			Type: "trademark",
		},
		TrademarkOwner: "VALENTINO S.P.A.",
	}

	// Create one event per URL found
	var result []*events.Event
	for _, url := range urlBlock {
		event := events.NewEvent("valentinobrandprotection")
		event.URL = url
		event.IP = ip
		event.EventTypes = []events.EventType{eventType}
		event.EventDate = eventDate

		// Add external ID detail
		event.AddEventDetail(&events.ExternalID{ID: ecin})

		result = append(result, event)
	}

	// Return error if no URLs were found
	if len(result) == 0 {
		return nil, common.NewParserError("no URLs found in email")
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
