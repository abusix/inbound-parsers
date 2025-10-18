package incopro

import (
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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Remove carriage returns
	body = common.RemoveCarriageReturn(body)

	// Extract owner and infringement URL
	pattern := regexp.MustCompile(`(.*)Notice of.*Infringement: (.*)`)
	matches := pattern.FindStringSubmatch(body)
	if len(matches) < 3 {
		return nil, common.NewParserError("could not find infringement notice pattern")
	}

	owner := strings.TrimSuffix(strings.TrimSpace(matches[1]), ":")
	infringement := strings.TrimSpace(matches[2])

	// Extract official URL
	officialURL := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Example of authorized work:", ""))

	// Determine event type based on subject and body
	var eventType events.EventType
	subjectLower := strings.ToLower(subject)
	bodyLower := strings.ToLower(body)

	if strings.Contains(subjectLower, "trademark") || strings.Contains(bodyLower, "trade mark") {
		trademark := events.NewTrademark("", nil, owner, "")
		trademark.OfficialURL = officialURL
		eventType = trademark
	} else if strings.Contains(subjectLower, "copyright") {
		copyright := events.NewCopyright("", owner, "")
		copyright.OfficialURL = officialURL
		eventType = copyright
	} else {
		return nil, common.NewNewTypeError(subjectLower)
	}

	// Get event date from email headers
	var eventDate = email.ParseDate(serializedEmail.Headers["date"][0])

	// Try to find the section with infringing URLs
	lines := []string{"content in question", "Please see infringement:", "Example of infringement"}
	var foundLine string
	for _, line := range lines {
		if strings.Contains(body, line) {
			foundLine = line
			break
		}
	}

	// If no marker line found, return single event with infringement URL
	if foundLine == "" {
		return returnSingleEvent(serializedEmail, eventType, infringement, eventDate), nil
	}

	// Get the first infringing URL and extract block around it
	firstInfringingURL := common.GetNonEmptyLineAfter(body, foundLine)
	blockLines := common.GetBlockAround(body, firstInfringingURL)

	// Extract all URLs from the block
	var result []*events.Event
	for _, line := range blockLines {
		trimmedLine := strings.TrimSpace(line)
		if strings.Contains(trimmedLine, "http") {
			event := events.NewEvent("incopro")
			event.EventDate = eventDate
			event.EventTypes = []events.EventType{eventType}
			event.URL = trimmedLine
			result = append(result, event)
		}
	}

	// If no events found, return single event with infringement URL
	if len(result) == 0 {
		return returnSingleEvent(serializedEmail, eventType, infringement, eventDate), nil
	}

	return result, nil
}

func returnSingleEvent(serializedEmail *email.SerializedEmail, eventType events.EventType, infringement string, eventDate *time.Time) []*events.Event {
	event := events.NewEvent("incopro")
	event.EventDate = eventDate
	event.EventTypes = []events.EventType{eventType}
	event.URL = infringement
	return []*events.Event{event}
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
