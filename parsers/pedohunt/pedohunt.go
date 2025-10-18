package pedohunt

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	ipPattern = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
)

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get body - throws error if empty
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Remove quote markers (> at start of lines)
	body = regexp.MustCompile(`(?m)^> ?`).ReplaceAllString(body, "")

	var eventsSlice []*events.Event

	// Get date from headers
	var eventDate *string
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = &dateHeader[0]
	}

	// Try to get data using GetBlockAround first
	data := common.GetBlockAround(body, "by this projects:")

	// Skip first element if found (marker line itself)
	if len(data) > 1 {
		data = data[1:]
	}

	// If no data, try GetBlockAfter
	if len(data) == 0 {
		data = common.GetBlockAfterWithStop(body, "by this projects:", "")
	}

	// Process each line
	for _, line := range data {
		event := events.NewEvent("pedohunt")

		if eventDate != nil {
			event.EventDate = email.ParseDate(*eventDate)
		}

		event.EventTypes = []events.EventType{events.NewChildAbuse()}

		// Check if line is an IP address
		line = strings.TrimSpace(line)
		if ipPattern.MatchString(line) {
			event.IP = line
		} else {
			event.URL = line
		}

		eventsSlice = append(eventsSlice, event)
	}

	return eventsSlice, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
