package swisscom

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// IP_PATTERN matches valid IPv4 addresses
var IP_PATTERN = regexp.MustCompile(
	`(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}` +
		`(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])`,
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	var eventList []*events.Event

	// Try to get body from main body or first part
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || strings.TrimSpace(body) == "" {
		// Try to get from first part
		if len(serializedEmail.Parts) > 0 {
			switch partBody := serializedEmail.Parts[0].Body.(type) {
			case string:
				body = partBody
			case []byte:
				body = string(partBody)
			}
		}
	}

	if body == "" {
		return nil, fmt.Errorf("no event created")
	}

	event := events.NewEvent("swisscom")

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	// Extract IP address
	if ipMatch := IP_PATTERN.FindString(body); ipMatch != "" {
		event.IP = ipMatch
	}

	// Clean up http references
	if !strings.Contains(body, "http") {
		body = strings.ReplaceAll(body, "hXXp", "http")
		body = strings.ReplaceAll(body, "hxxp", "http")
	}

	// Extract phishing URL
	startIndexPhishingURL := strings.Index(body, "http")
	if startIndexPhishingURL != -1 {
		endIndexPhishingURL := strings.Index(body[startIndexPhishingURL:], "<")
		var phishingURL string
		if endIndexPhishingURL != -1 {
			phishingURL = body[startIndexPhishingURL : startIndexPhishingURL+endIndexPhishingURL]
		} else {
			// If no '<' found, take rest of string or until whitespace
			remaining := body[startIndexPhishingURL:]
			if spaceIdx := strings.IndexAny(remaining, " \n\r\t"); spaceIdx != -1 {
				phishingURL = remaining[:spaceIdx]
			} else {
				phishingURL = remaining
			}
		}
		phishingURL = strings.ReplaceAll(phishingURL, "[.]", ".")
		event.URL = phishingURL

		// Set phishing event type
		event.EventTypes = []events.EventType{events.NewPhishing()}
	}

	eventList = append(eventList, event)

	if len(eventList) == 0 {
		return nil, fmt.Errorf("no event created")
	}

	return eventList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
