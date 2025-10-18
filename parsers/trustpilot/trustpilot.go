package trustpilot

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
	// Get subject - throws error if not available
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Get body - throws error if not available
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)
	bodyLower := strings.ToLower(body)

	// Check if this is a takedown request
	if !strings.Contains(subjectLower, "takedown request") &&
		!strings.Contains(subjectLower, "take down request") &&
		!strings.Contains(subjectLower, "takedown notice") {
		return nil, common.NewParserError("not a takedown request")
	}

	// Create event template
	eventTemplate := events.NewEvent("trustpilot")

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate := email.ParseDate(dateHeaders[0])
		eventTemplate.EventDate = eventDate
	}

	// Extract trademark owner
	owner := common.FindStringWithoutMarkers(body, "\n", "(hereinafter ")
	owner = strings.TrimSpace(owner)

	// Check if EUTM (European Union Trademark) is mentioned
	if strings.Contains(body, "EUTM") {
		// Extract registration numbers using regex
		re := regexp.MustCompile(`EU(\d{4,})`)
		matches := re.FindAllStringSubmatch(body, -1)

		// Use a set to eliminate duplicates
		registrationNumbersMap := make(map[string]bool)
		for _, match := range matches {
			if len(match) > 1 {
				registrationNumbersMap[match[1]] = true
			}
		}

		// Convert map to slice
		var registrationNumbers []string
		for num := range registrationNumbersMap {
			registrationNumbers = append(registrationNumbers, num)
		}

		// Create Trademark event type with EUTM
		trademark := &events.Trademark{
			BaseEventType: events.BaseEventType{
				Name: "trademark",
				Type: "trademark",
			},
			TrademarkOwner:      owner,
			RegistrationOffice:  "EUTM",
			RegistrationNumbers: registrationNumbers,
		}
		eventTemplate.EventTypes = []events.EventType{trademark}
	} else {
		// Create Trademark event type without registration office
		trademark := &events.Trademark{
			BaseEventType: events.BaseEventType{
				Name: "trademark",
				Type: "trademark",
			},
			TrademarkOwner: owner,
		}
		eventTemplate.EventTypes = []events.EventType{trademark}
	}

	// Check for URLs in body
	var eventsList []*events.Event

	if strings.Contains(bodyLower, "the following urls:") {
		// Extract URLs from the block after the marker
		urls := common.GetBlockAfter(bodyLower, "the following urls:")

		for _, url := range urls {
			// Create a copy of the event template
			event := events.NewEvent("trustpilot")
			event.EventDate = eventTemplate.EventDate
			event.EventTypes = eventTemplate.EventTypes
			event.URL = url
			eventsList = append(eventsList, event)
		}
	} else {
		// Use subject as URL
		eventTemplate.URL = subjectLower
		eventsList = append(eventsList, eventTemplate)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no events created")
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
