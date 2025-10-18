package fondia

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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Extract copyright owner from the body
	copyrightOwner := common.FindStringWithoutMarkers(body, "Respectfully on behalf of", ",")
	copyrightOwner = strings.TrimSpace(copyrightOwner)

	// Find the first non-empty line after the marker
	firstLine := common.GetNonEmptyLineAfter(body, "Location of potential infringement")

	// Get the block of lines around the first line (which should contain URLs)
	urlLines := common.GetBlockAround(body, firstLine)

	// Extract unique URLs that start with "http"
	uniqueURLs := make(map[string]bool)
	for _, line := range urlLines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "http") {
			uniqueURLs[line] = true
		}
	}

	// Create events for each unique URL
	var result []*events.Event
	for url := range uniqueURLs {
		event := events.NewEvent("fondia")

		// Set the URL
		event.URL = url

		// Set the event date from headers
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}

		// Create Trademark event type with the copyright owner
		trademark := events.NewTrademark("", nil, copyrightOwner, "")
		event.EventTypes = []events.EventType{trademark}

		result = append(result, event)
	}

	// If no events were created, return an error
	if len(result) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
