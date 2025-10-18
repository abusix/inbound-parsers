package mirrorimagegaming

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the parser
type Parser struct{}

// Parse converts a mirrorimagegaming email into abuse events
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	var dateStr string
	var targetIP string

	// Try to extract from parts or body
	if len(serializedEmail.Parts) > 1 {
		// Has multiple parts - get from second part
		switch log := serializedEmail.Parts[1].Body.(type) {
		case string:
			targetIP = common.FindStringWithoutMarkers(log, "DST=", " ")

			// Extract date with DROP pattern
			dropPattern := regexp.MustCompile(`(.*) DROP`)
			if matches := dropPattern.FindStringSubmatch(log); len(matches) > 1 {
				dateStr = matches[1]
			}
		}
	} else {
		// Single part - use body
		switch log := serializedEmail.Body.(type) {
		case string:
			targetIP = common.FindStringWithoutMarkers(log, "→", " ")

			// Extract date with pattern: Mon DD HH:MM:SS
			datePattern := regexp.MustCompile(`([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})`)
			if matches := datePattern.FindStringSubmatch(log); len(matches) > 1 {
				dateStr = matches[1]
			}
		}
	}

	// Parse the date, adding year if needed
	eventDate := email.ParseDate(dateStr)
	if dateStr != "" && eventDate == nil {
		// Try adding year from email header date
		parts := strings.Fields(dateStr)
		if len(parts) >= 3 {
			month := parts[0]
			day := parts[1]
			timeStr := parts[2]

			// Get year from email header
			if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
				if headerDate := email.ParseDate(dateHeaders[0]); headerDate != nil {
					year := headerDate.Year()
					dateStr = fmt.Sprintf("%s %s %d %s", month, day, year, timeStr)
					eventDate = email.ParseDate(dateStr)
				}
			}
		}
	}

	event := events.NewEvent("mirrorimagegaming")
	event.EventTypes = []events.EventType{events.NewDDoS()}
	event.EventDate = eventDate

	if targetIP != "" {
		event.AddEventDetail(&events.Target{
			IP: targetIP,
		})
	}

	event.IP = body

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
