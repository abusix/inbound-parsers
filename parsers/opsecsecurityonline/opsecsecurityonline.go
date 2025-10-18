package opsecsecurityonline

import (
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
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	// Check if 'phish' is in body
	if !strings.Contains(strings.ToLower(body), "phish") {
		return nil, common.NewNewTypeError(subject)
	}

	// Get URLs from the block after 'The URL'
	urls := common.GetBlockAfterWithStop(body, "The URL", "")

	// Get IP from the line after 'The IP'
	ipStr := common.FindStringWithoutMarkers(body, "The IP", "")

	// Remove spaces from URLs
	var cleanedURLs []string
	for _, url := range urls {
		cleanedURL := strings.ReplaceAll(url, " ", "")
		if cleanedURL != "" {
			cleanedURLs = append(cleanedURLs, cleanedURL)
		}
	}

	// Create events
	var eventsList []*events.Event
	for _, url := range cleanedURLs {
		event := events.NewEvent("opsecsecurityonline")
		event.EventTypes = []events.EventType{events.NewPhishing()}
		event.URL = url
		event.IP = common.ExtractOneIP(ipStr)

		// Set event date from headers
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}

		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
