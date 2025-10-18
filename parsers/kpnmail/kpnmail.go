package kpnmail

import (
	"regexp"
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

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, common.NewParserError("failed to get email body: " + err.Error())
	}

	// Get event date from headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	// Extract the block after "see below."
	eventBlock := common.GetBlockAfterWithStop(body, "see below.", "")

	if len(eventBlock) == 0 {
		return nil, common.NewParserError("no event block found after 'see below.'")
	}

	var eventsList []*events.Event

	// Regex to match URL pattern: url ---> IP
	urlPattern := regexp.MustCompile(`(?P<url>\S+)\s+--->\s+[\d.]+`)

	for _, line := range eventBlock {
		event := events.NewEvent("kpnmail")
		event.EventTypes = []events.EventType{events.NewSpam()}
		event.EventDate = eventDate

		// Try to extract URL
		if matches := urlPattern.FindStringSubmatch(line); matches != nil {
			url := matches[1] // First captured group is the URL

			// Add scheme if missing
			if !strings.Contains(url, "http") {
				url = "https://" + url
			}

			event.URL = url
		}

		// Extract IP from the line
		if ip := common.ExtractOneIP(line); ip != "" {
			event.IP = ip
		}

		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no events created from email body")
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
