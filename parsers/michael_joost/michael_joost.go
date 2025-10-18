package michael_joost

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

	// Extract target IP from body
	targetIP := common.FindStringWithoutMarkers(body, "last incident seen on IP", "")
	targetIP = strings.Trim(targetIP, ". ")

	var result []*events.Event

	// Parse each line looking for date patterns
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		if datePattern.MatchString(line) {
			event := events.NewEvent("michael_joost")
			event.IP = subject
			event.EventTypes = []events.EventType{events.NewPortScan()}

			// Parse the line: format is space-separated with:
			// [0] = date, [1] = source_port, [2] = target_port, [4] = date, [5] = time
			data := strings.Fields(line)
			if len(data) < 6 {
				continue // Skip malformed lines
			}

			sourcePort := data[1]
			targetPort := data[2]
			eventDate := data[4] + " " + data[5]

			// Set source port on event
			sourcePortNum, err := common.ParsePort(sourcePort)
			if err == nil {
				event.Port = sourcePortNum
			}

			// Add target detail with target IP and port
			event.AddEventDetail(&events.Target{
				IP:   targetIP,
				Port: targetPort,
			})

			// Parse event date
			eventDateTime := email.ParseDate(eventDate)
			if eventDateTime != nil {
				event.EventDate = eventDateTime
			}

			result = append(result, event)
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no events created")
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
