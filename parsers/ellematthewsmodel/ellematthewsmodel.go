// Package ellematthewsmodel implements the ellematthewsmodel parser
package ellematthewsmodel

import (
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the ellematthewsmodel parser
type Parser struct{}

// NewParser creates a new Parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails for ellematthewsmodel
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Extract official website
	officialWebsite := common.FindStringWithoutMarkers(body, "official website", "<")

	// Extract IP address
	ip := common.GetNonEmptyLineAfter(body, "IP Address")

	// Extract URLs based on different patterns
	var urls []string

	// Try first pattern: "reported below:" to "Web Host"
	urlsBlock := common.FindStringWithoutMarkers(body, "reported below:", "Web Host")
	if urlsBlock != "" {
		lines := strings.Split(urlsBlock, "\n")
		for _, line := range lines {
			if strings.Contains(line, "http") {
				urls = append(urls, strings.TrimSpace(line))
			}
		}
	} else {
		// Try second pattern: "requesting for Takedown" to "Web Host" with Thumbnail
		urlsBlock = common.FindStringWithoutMarkers(body, "requesting for Takedown", "Web Host")
		if urlsBlock != "" && strings.Contains(body, "Thumbnail") {
			lines := strings.Split(urlsBlock, "\n")
			for _, line := range lines {
				if strings.Contains(line, "http") {
					// Extract URL between <http and .jpg>
					extracted := common.FindString(line, "<http", ".jpg")
					if extracted != "" {
						// Strip the leading '<'
						extracted = strings.TrimPrefix(extracted, "<")
						urls = append(urls, extracted)
					}
				}
			}
		}
	}

	// If no URLs found, return error
	if len(urls) == 0 {
		return nil, common.NewParserError("no url block found adapt the parser")
	}

	// Get event date from email headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	// Create events for each URL
	var eventsList []*events.Event
	for _, url := range urls {
		event := events.NewEvent("ellematthewsmodel")
		copyright := events.NewCopyright("", "", "")
		copyright.OfficialURL = officialWebsite
		event.EventTypes = []events.EventType{copyright}
		event.URL = url
		event.IP = ip
		event.EventDate = eventDate
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
