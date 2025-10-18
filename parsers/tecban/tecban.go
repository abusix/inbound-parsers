package tecban

import (
	"fmt"
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
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	event := events.NewEvent("tecban")

	// Parse event date - try to find date in body first
	datePattern := regexp.MustCompile(`(?i)\w{3} \d+, \d{4}, \d{2}:\d{2}:\d{2} (am|pm)`)
	if dateMatch := datePattern.FindString(body); dateMatch != "" {
		// Parse format like "Jan 15, 2024, 10:30:45 PM"
		// Need to handle 12-hour format with AM/PM
		parsedTime, err := time.Parse("Jan 2, 2006, 03:04:05 PM", dateMatch)
		if err == nil {
			event.EventDate = &parsedTime
		}
	}

	// If no date found in body, use email date header
	if event.EventDate == nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
				event.EventDate = parsedDate
			}
		}
	}

	// Extract IP from subject (replace underscores with dots)
	// The subject contains the IP with underscores like "1_2_3_4"
	ipFromSubject := strings.ReplaceAll(subjectLower, "_", ".")

	// Try to validate if it's a proper IP
	ipPattern := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	if ipMatch := ipPattern.FindString(ipFromSubject); ipMatch != "" {
		event.IP = ipMatch
	} else {
		// Fallback: try to find IP in body after "Source IP"
		ipFromBody := common.GetNonEmptyLineAfter(body, "Source IP")
		if ipFromBody != "" {
			if ipMatch := ipPattern.FindString(ipFromBody); ipMatch != "" {
				event.IP = ipMatch
			}
		}
	}

	// Determine event type based on subject
	if strings.Contains(subjectLower, "malicious activity") {
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
	} else {
		// If subject doesn't match known patterns, return error
		return nil, fmt.Errorf("unknown event type in subject: %s", subject)
	}

	// Extract source/destination IP, ports from body
	// Pattern: <source_ip> <source_port> <dest_ip> <dest_port>
	if event.IP != "" {
		// Escape dots in IP for regex
		escapedIP := regexp.QuoteMeta(event.IP)
		eventPattern := regexp.MustCompile(escapedIP + `\s+(?P<port>\d+)\s+(?P<dest_ip>(?:\d{1,3}\.){3}\d{1,3})\s+(?P<dest_port>\d+)`)

		if match := eventPattern.FindStringSubmatch(body); match != nil {
			// Extract named groups
			portIdx := eventPattern.SubexpIndex("port")
			destIPIdx := eventPattern.SubexpIndex("dest_ip")
			destPortIdx := eventPattern.SubexpIndex("dest_port")

			if portIdx != -1 && portIdx < len(match) {
				port := match[portIdx]
				if portNum, err := common.ParsePort(port); err == nil {
					event.Port = portNum
				}
			}

			if destIPIdx != -1 && destPortIdx != -1 && destIPIdx < len(match) && destPortIdx < len(match) {
				destinationIP := match[destIPIdx]
				destinationPort := match[destPortIdx]

				// Add target as event detail
				event.AddEventDetail(&events.Target{
					IP:   destinationIP,
					Port: destinationPort,
				})
			}
		}
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
