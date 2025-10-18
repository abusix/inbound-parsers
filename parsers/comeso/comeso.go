package comeso

import (
	"regexp"
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

	if len(body) == 0 {
		return nil, common.NewParserError("no event created")
	}

	var eventsList []*events.Event

	// Extract external ID
	externalIDStr := strings.TrimSpace(common.FindStringWithoutMarkers(body, "ID:", ""))
	if externalIDStr == "" {
		return nil, common.NewParserError("external ID not found")
	}
	externalID := &events.ExternalID{ID: externalIDStr}

	// Extract IP
	ip := common.FindStringWithoutMarkers(body, "IP:", "")

	// Variables to hold copyrighted work info
	var work, originalURL string

	// Process each line to extract work info and URLs
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		// Remove '>' and trim
		line = strings.TrimSpace(strings.ReplaceAll(line, ">", ""))

		// Check for "Original Work:" line
		if strings.HasPrefix(line, "Original Work:") {
			workInfo := common.FindStringWithoutMarkers(line, "Original Work:", ")")
			parts := strings.Split(workInfo, "(")
			if len(parts) == 2 {
				work = strings.TrimSpace(parts[0])
				originalURL = strings.TrimSpace(parts[1])
			}
			continue
		}

		// Check if line starts with http
		if !strings.HasPrefix(line, "http") {
			continue
		}

		// Create event for this URL
		event := events.NewEvent("comeso")

		// Set event date from email headers
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}

		event.URL = line
		event.IP = ip
		event.AddEventDetail(externalID)

		// Create Copyright event type
		copyright := events.NewCopyright(work, "", "")
		copyright.OfficialURL = originalURL
		event.EventTypes = []events.EventType{copyright}

		eventsList = append(eventsList, event)
	}

	// If no events created, try to extract URL from subject
	if len(eventsList) == 0 {
		subject, _ := common.GetSubject(serializedEmail, false)

		// Use regex to find URL in parentheses in subject
		re := regexp.MustCompile(`\((.*)\)`)
		matches := re.FindStringSubmatch(subject)

		if len(matches) > 1 {
			event := events.NewEvent("comeso")

			// Set event date from email headers
			if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
				event.EventDate = email.ParseDate(dateHeaders[0])
			}

			event.URL = matches[1]
			event.AddEventDetail(externalID)

			// Create Copyright event type with no work info
			copyright := events.NewCopyright("", "", "")
			event.EventTypes = []events.EventType{copyright}

			eventsList = append(eventsList, event)
		}
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
