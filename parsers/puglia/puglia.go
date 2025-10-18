// Package puglia implements the puglia parser
package puglia

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the puglia parser
type Parser struct{}

// Parse parses emails from noreply@ct.rupar.puglia.it
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	event := events.NewEvent("puglia")

	if len(body) > 0 {
		lines := strings.Split(body, "\n")
		for _, line := range lines {
			// Strip HTML tags and whitespace
			line = strings.Trim(line, " <p></p>")

			if strings.Contains(line, "Date: ") {
				// Extract date and append time
				dateStr := strings.TrimPrefix(line, "Date: ")
				dateStr = strings.TrimSpace(dateStr) + " 00:00:00"
				eventDate := email.ParseDate(dateStr)
				event.EventDate = eventDate
			} else if strings.Contains(line, "Source IP address: ") {
				// Extract source IP
				ip := strings.TrimPrefix(line, "Source IP address: ")
				event.IP = strings.TrimSpace(ip)
			} else if strings.Contains(line, "Destination IP address: ") {
				// Extract destination IP as target
				destIP := strings.TrimPrefix(line, "Destination IP address: ")
				target := &events.Target{
					IP: strings.TrimSpace(destIP),
				}
				event.AddEventDetail(target)
			} else if strings.Contains(line, "Description:  ") {
				// Extract description
				desc := strings.TrimPrefix(line, "Description:  ")
				desc = strings.TrimSpace(desc)
				if desc != "" {
					event.AddEventDetailSimple("description", desc)
				}
			}
		}

		// Set event type to exploit
		event.EventTypes = []events.EventType{events.NewExploit()}
	}

	if event.IP == "" && event.EventDate == nil {
		return nil, common.NewParserError("no event created")
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
