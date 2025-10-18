package interhost

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// DATE_PATTERN matches time formats like "Aug 10 14:23:31" or "2024-08-10 14:23:31"
var DATE_PATTERN = regexp.MustCompile(`[A-Za-z]{3}\s*\d{1,2}\s*\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}\s*\d{2}:\d{2}:\d{2}`)

// IP_PATTERN matches valid IP addresses with port separated using '/'. Example: 138.68.254.243/39181
var IP_PATTERN = regexp.MustCompile(`(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])/\d{1,5}`)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	var eventList []*events.Event

	// Get year from email date header
	var year int
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		if parsedDate := email.ParseDate(dateHeader[0]); parsedDate != nil {
			year = parsedDate.Year()
		}
	}

	// Get subject (should be the IP)
	var subjectIP string
	if subject, ok := serializedEmail.Headers["subject"]; ok && len(subject) > 0 {
		subjectIP = subject[0]
	}

	// Parse body line by line looking for IP patterns
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		ipMatches := IP_PATTERN.FindAllString(line, -1)
		if len(ipMatches) >= 2 {
			source := ipMatches[0]
			target := ipMatches[1]

			// Extract source port
			sourcePort := ""
			if idx := strings.LastIndex(source, "/"); idx != -1 {
				sourcePort = source[idx+1:]
			}

			// Extract target IP and port
			targetIP := ""
			targetPort := ""
			if idx := strings.LastIndex(target, "/"); idx != -1 {
				targetIP = target[:idx]
				targetPort = target[idx+1:]
			}

			// Find date in the line
			dateMatches := DATE_PATTERN.FindAllString(line, -1)
			if len(dateMatches) > 0 {
				dateStr := dateMatches[0]

				event := events.NewEvent("interhost")
				event.IP = subjectIP

				// Set event date
				if strings.Contains(dateStr, "-") {
					// Already has year in format "2024-08-10 14:23:31"
					event.EventDate = email.ParseDate(dateStr)
				} else {
					// Format like "Aug 10 14:23:31" - need to add year
					event.EventDate = email.ParseDate(fmt.Sprintf("%d %s", year, dateStr))
				}

				// Set port from source
				if sourcePort != "" {
					if port, err := strconv.Atoi(sourcePort); err == nil {
						event.Port = port
					}
				}

				// Add target information
				event.AddEventDetail(&events.Target{
					IP:   targetIP,
					Port: targetPort,
				})

				// Set event type
				event.EventTypes = []events.EventType{events.NewExploit()}

				eventList = append(eventList, event)
			}
		}
	}

	// If no events were created from parsing, create a minimal event
	if len(eventList) == 0 {
		event := events.NewEvent("interhost")
		event.IP = subjectIP

		// Use date from email header
		if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
			event.EventDate = email.ParseDate(dateHeader[0])
		}

		event.EventTypes = []events.EventType{events.NewExploit()}
		eventList = append(eventList, event)
	}

	if len(eventList) == 0 {
		return nil, fmt.Errorf("no event created")
	}

	return eventList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
