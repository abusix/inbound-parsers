package realityripple

import (
	"fmt"
	"strings"

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

	event := events.NewEvent("realityripple")

	// Extract and set event type based on abuse type
	abuseType := strings.ToLower(common.FindStringWithoutMarkers(body, "Type of Abuse:", ""))
	if strings.Contains(abuseType, "intrusion") {
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	} else if strings.Contains(abuseType, "spam") {
		event.EventTypes = []events.EventType{events.NewSpam()}
	}

	// Extract abusive IP
	event.IP = strings.TrimSpace(common.FindStringWithoutMarkers(body, "Abusive IP:", ""))

	// Extract and parse target information
	targetStr := strings.ReplaceAll(common.FindStringWithoutMarkers(body, "Target:", ""), ")", "")
	parts := strings.Split(targetStr, "(")
	if len(parts) >= 2 {
		targetIP := strings.TrimSpace(parts[0])
		targetURL := strings.TrimSpace(parts[1])
		event.AddEventDetail(&events.Target{
			IP:  targetIP,
			URL: targetURL,
		})
	}

	// Extract and parse event date
	timeOfBan := common.FindStringWithoutMarkers(body, "Time of Ban:", "")
	banParts := strings.Split(timeOfBan, ",")
	if len(banParts) >= 2 {
		monthAndDay := banParts[0]
		yearAndTimePart := strings.TrimSpace(strings.Join(banParts[1:], ","))

		// Split year and time
		yearTimeParts := strings.Split(yearAndTimePart, " at ")
		if len(yearTimeParts) >= 2 {
			year := strings.TrimSpace(yearTimeParts[0])
			timeStr := strings.TrimSpace(yearTimeParts[1])

			// Pad time with leading zero if needed
			if len(timeStr) > 0 && timeStr[1] == ':' {
				timeStr = "0" + timeStr
			}

			// Construct date string
			dateStr := fmt.Sprintf("%s, %s %s", strings.TrimSuffix(strings.TrimSpace(monthAndDay), "st"), year, timeStr)
			dateStr = strings.TrimSuffix(dateStr, "nd")
			dateStr = strings.TrimSuffix(dateStr, "rd")
			dateStr = strings.TrimSuffix(dateStr, "th")

			event.EventDate = email.ParseDate(dateStr)
		}
	}

	if event.IP == "" && len(event.EventDetails) == 0 {
		return nil, fmt.Errorf("no event created")
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
