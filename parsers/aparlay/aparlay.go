package aparlay

import (
	"fmt"
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
		return nil, err
	}

	// Remove carriage returns as in Python version
	body = common.RemoveCarriageReturn(body)

	// Extract IP address
	ip := common.FindStringWithoutMarkers(body, "IP:", "")
	if ip == "" {
		return nil, fmt.Errorf("could not find IP in email body")
	}
	ip = strings.TrimSpace(ip)
	// Get first line if there are multiple lines
	if idx := strings.Index(ip, "\n"); idx != -1 {
		ip = ip[:idx]
	}
	ip = strings.TrimSpace(ip)

	// Extract and parse timestamp
	timestampStr := common.FindStringWithoutMarkers(body, "Timestamp:", "")
	if timestampStr == "" {
		return nil, fmt.Errorf("could not find Timestamp in email body")
	}

	// Get first line only if there are multiple lines
	if idx := strings.Index(timestampStr, "\n"); idx != -1 {
		timestampStr = timestampStr[:idx]
	}
	timestampStr = strings.TrimSpace(timestampStr)

	// Parse the timestamp according to Python version:
	// _, day, _, month, year, time, a, zone, _ = timestamp.strip().split(' ')
	// Example from sample: "Tuesday 20th of April 2021 07:34:04 AM UTC Time"
	// Split and expect at least 7 parts
	parts := strings.Fields(timestampStr)
	if len(parts) < 7 {
		return nil, fmt.Errorf("date format changed, got: %s", timestampStr)
	}

	// According to Python code that splits on spaces:
	// parts[0] = weekday (Tuesday)
	// parts[1] = day with ordinal (20th)
	// parts[2] = "of"
	// parts[3] = month (April)
	// parts[4] = year (2021)
	// parts[5] = time (07:34:04)
	// parts[6] = AM/PM (AM)
	// parts[7] = zone (UTC)
	// parts[8] = "Time" (optional)

	day := strings.TrimSuffix(parts[1], "st")
	day = strings.TrimSuffix(day, "nd")
	day = strings.TrimSuffix(day, "rd")
	day = strings.TrimSuffix(day, "th")
	month := parts[3]
	year := parts[4]
	timePart := parts[5]
	ampm := parts[6]
	zone := ""
	if len(parts) >= 8 {
		zone = parts[7]
	}

	// Extract hour and minute from time (HH:MM:SS -> HH:MM)
	timeComponents := strings.Split(timePart, ":")
	if len(timeComponents) < 2 {
		return nil, fmt.Errorf("invalid time format: %s", timePart)
	}
	hour := timeComponents[0]
	minute := timeComponents[1]

	// Reconstruct date string as in Python: f'{day} {month} {year} {hour}:{minute} {a} {zone}'
	dateStr := fmt.Sprintf("%s %s %s %s:%s %s %s", day, month, year, hour, minute, ampm, zone)

	// Parse the date string
	// Format: "20 April 2021 07:34 AM UTC"
	eventDate, err := time.Parse("2 January 2006 3:04 PM MST", dateStr)
	if err != nil {
		// Try without timezone
		dateStrNoZone := fmt.Sprintf("%s %s %s %s:%s %s", day, month, year, hour, minute, ampm)
		eventDate, err = time.Parse("2 January 2006 3:04 PM", dateStrNoZone)
		if err != nil {
			return nil, fmt.Errorf("could not parse event date '%s': %w", dateStr, err)
		}
	}

	// Create event
	event := events.NewEvent("aparlay")
	event.IP = ip
	event.EventDate = &eventDate
	event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

	// Extract targets (optional, errors are ignored)
	targetsStr := common.FindStringWithoutMarkers(body, "service being attacked:", "Thank you")
	if targetsStr != "" {
		targetsStr = strings.ReplaceAll(targetsStr, "\n", " ")
		targetsStr = strings.TrimSpace(targetsStr)

		// Parse targets: comma-separated "URL IP" pairs
		targetPairs := strings.Split(targetsStr, ",")
		var targets []*events.Target

		for _, pair := range targetPairs {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}

			// Split by space: "URL IP"
			parts := strings.Fields(pair)
			if len(parts) >= 2 {
				target := &events.Target{
					URL: parts[0],
					IP:  parts[1],
				}
				targets = append(targets, target)
			}
		}

		// Add targets to event details if we found any
		if len(targets) > 0 {
			for _, target := range targets {
				event.AddEventDetail(target)
			}
		}
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
