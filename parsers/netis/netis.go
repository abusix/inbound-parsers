package netis

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

var datePattern = regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	var eventsSlice []*events.Event
	seenIPs := make(map[string]bool)

	lines := strings.Split(body, "\n")
	for _, line := range lines {
		if datePattern.MatchString(line) {
			// Split on '=>' to separate date_ip from target_ip
			parts := strings.Split(line, "=>")
			if len(parts) != 2 {
				continue
			}

			dateIP := strings.TrimSpace(parts[0])
			targetIP := strings.TrimSpace(parts[1])

			// Extract date from date_ip part (split on ': ')
			dateParts := strings.Split(dateIP, ": ")
			if len(dateParts) < 1 {
				continue
			}
			dateStr := dateParts[0]

			// Extract target IP and port from target_ip part
			// Format is "IP:PORT ..." so split on ':' and then on space
			targetParts := strings.Split(targetIP, ":")
			if len(targetParts) < 2 {
				continue
			}
			tarIP := strings.TrimSpace(targetParts[0])

			// Get port (may have trailing content after space)
			portParts := strings.Fields(targetParts[1])
			if len(portParts) < 1 {
				continue
			}
			tarPort := portParts[0]

			// Use subject as the source IP
			sourceIP := subject

			// Only create event if we haven't seen this IP before
			if !seenIPs[sourceIP] {
				seenIPs[sourceIP] = true

				event := events.NewEvent("netis")
				event.IP = sourceIP

				// Parse event date
				eventDate := email.ParseDate(dateStr)
				if eventDate != nil {
					event.EventDate = eventDate
				}

				// Add target information
				event.AddEventDetail(&events.Target{
					IP:   tarIP,
					Port: tarPort,
				})

				// Set event type to PortScan
				event.EventTypes = []events.EventType{events.NewPortScan()}

				eventsSlice = append(eventsSlice, event)
			}
		}
	}

	if len(eventsSlice) == 0 {
		return nil, fmt.Errorf("no event created")
	}

	return eventsSlice, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
