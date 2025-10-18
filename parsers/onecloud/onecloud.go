package onecloud

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

	event := events.NewEvent("onecloud")

	// Get IP from subject
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	event.IP = subject

	var date string
	var timezone string
	targetSet := make(map[string]bool)

	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")

		// Check for date pattern
		if datePattern.MatchString(line) {
			// Extract target IP from the line
			_, after, _ := strings.Cut(line, " ")
			targetIP := strings.Trim(after, "=0A=")

			// Skip if contains .xx (redacted IP)
			if !strings.Contains(strings.ToLower(targetIP), ".xx") {
				targetSet[targetIP] = true
			}

			// Extract date (first 19 characters: YYYY-MM-DD HH:MM:SS)
			if len(line) >= 19 {
				date = line[:19]
			}
		} else if strings.HasPrefix(line, "Timezone") {
			// Extract timezone from format like "Timezone (+X)" or "Timezone (+XX)"
			indexSign := strings.Index(line, "(") + 1
			indexClosingPar := strings.Index(line, ")")

			if indexSign > 0 && indexClosingPar > indexSign {
				tzContent := line[indexSign:indexClosingPar]
				if indexClosingPar-indexSign == 2 {
					// Single digit timezone like (+3)
					timezone = fmt.Sprintf("%s0%s:00", string(tzContent[0]), string(tzContent[1]))
				} else if len(tzContent) >= 3 {
					// Two digit timezone like (+13)
					timezone = fmt.Sprintf("%s1%s:00", string(tzContent[0]), string(tzContent[2]))
				}
			}
		}
	}

	// Get target from set
	var target string
	var targetPort string
	for t := range targetSet {
		target = t
		break
	}

	// Extract port if present
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		if len(parts) > 0 {
			targetPort = parts[len(parts)-1]
		}
	}

	// Add target details
	event.AddEventDetail(&events.Target{
		IP:   target,
		Port: targetPort,
	})

	// Set event date
	if date != "" && timezone != "" {
		dateStr := date + timezone
		eventDate := email.ParseDate(dateStr)
		event.EventDate = eventDate
	} else if date != "" {
		// Even if timezone is nil, still set the date with timezone
		dateStr := date + timezone
		eventDate := email.ParseDate(dateStr)
		event.EventDate = eventDate
	}

	// Set event type
	event.EventTypes = []events.EventType{events.NewPortScan()}

	eventsList := []*events.Event{event}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
