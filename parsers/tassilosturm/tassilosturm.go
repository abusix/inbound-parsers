package tassilosturm

import (
	"regexp"
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
		return nil, err
	}

	// Create event template with Bot event type
	eventTemplate := events.NewEvent("tassilosturm")
	eventTemplate.EventTypes = []events.EventType{events.NewBot("")}

	// Search for target IP (destination/victim)
	targetPattern1 := regexp.MustCompile(`(?i)destination ip address \(my ip\)\s*(\S+)`)
	targetPattern2 := regexp.MustCompile(`(?i)my own ip:\s*(\S+)`)

	if match := targetPattern1.FindStringSubmatch(body); match != nil {
		target := &events.Target{IP: match[1]}
		eventTemplate.AddEventDetail(target)
	} else if match := targetPattern2.FindStringSubmatch(body); match != nil {
		target := &events.Target{IP: match[1]}
		eventTemplate.AddEventDetail(target)
	}

	var result []*events.Event

	// First pattern: spam-ip format
	spamIPPattern := regexp.MustCompile(`(?i)spam-ip:\s+(\S+)`)
	if match := spamIPPattern.FindStringSubmatch(body); match != nil {
		eventTemplate.IP = match[1]

		// Extract event date
		datePattern := regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}`)
		if dateMatch := datePattern.FindStringSubmatch(body); dateMatch != nil {
			if eventDate, err := time.Parse("2006-01-02 15:04:05", dateMatch[0]); err == nil {
				eventTemplate.EventDate = &eventDate
			}
		}

		result = append(result, eventTemplate)
	} else {
		// Second pattern: table format with date, unknown column, and IP
		entryPattern := regexp.MustCompile(`(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})[ \t]+\S+[ \t]+(\S+)`)
		matches := entryPattern.FindAllStringSubmatch(body, -1)

		// Track unique IPs to avoid duplicates
		seenIPs := make(map[string]bool)

		for _, match := range matches {
			if len(match) >= 3 {
				ip := match[2]

				// Skip if we've already seen this IP
				if seenIPs[ip] {
					continue
				}
				seenIPs[ip] = true

				// Create a copy of the event template for each unique IP
				event := events.NewEvent("tassilosturm")
				event.EventTypes = []events.EventType{events.NewBot("")}

				// Copy event details from template
				for _, detail := range eventTemplate.EventDetails {
					event.AddEventDetail(detail)
				}

				// Set IP and event date
				event.IP = ip
				if eventDate, err := time.Parse("2006-01-02 15:04:05", match[1]); err == nil {
					event.EventDate = &eventDate
				}

				result = append(result, event)
			}
		}
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
