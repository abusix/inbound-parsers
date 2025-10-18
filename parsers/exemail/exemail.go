// Package exemail implements the exemail parser
package exemail

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the exemail parser
type Parser struct{}

var datePattern = regexp.MustCompile(`\d{4}:\d{2}:\d{2}:\d{2}`)

// Parse parses emails from marksitkowski@exemail.com.au for bot reports
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	for _, line := range strings.Split(body, "\n") {
		if datePattern.MatchString(line) {
			event := events.NewEvent("exemail")
			parts := strings.Fields(line)
			if len(parts) > 0 {
				event.IP = parts[0]
			}
			dateStr := common.FindStringWithoutMarkers(line, "[", "]")
			event.EventDate = email.ParseDate(dateStr)
			event.EventTypes = []events.EventType{events.NewBot("")}
			return []*events.Event{event}, nil
		}
	}

	return nil, common.NewParserError("Date not found, no incident created.")
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
