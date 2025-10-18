package telus

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

var caseNumberRe = regexp.MustCompile(`Registration No\.:\s+(?P<number>.*)`)

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

	// Extract case number from subject (between '#' and ']')
	caseNum := common.FindStringWithoutMarkers(subject, "#", "]")

	// Extract trademark owner (between 'Trademark:' and next line)
	owner := common.FindStringWithoutMarkers(body, "Trademark:", "")
	owner = strings.Trim(owner, " \"")

	// Extract country (between 'Country:' and next line)
	country := common.FindStringWithoutMarkers(body, "Country:", "")
	country = strings.Trim(country, " \"")

	// Extract all registration numbers
	var registrationNumbers []string
	matches := caseNumberRe.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 {
			registrationNumbers = append(registrationNumbers, match[1])
		}
	}

	// Get URLs from the block after "following websites"
	urls := common.GetBlockAfterWithStop(body, "following websites", "")

	// Parse the event date from headers
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	// Create an event for each URL
	var result []*events.Event
	for _, url := range urls {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}

		event := events.NewEvent("telus")
		event.URL = url
		event.EventDate = eventDate

		// Add external ID (case number)
		if caseNum != "" {
			event.AddEventDetail(&events.ExternalID{ID: caseNum})
		}

		// Add trademark event type
		trademark := &events.Trademark{
			BaseEventType: events.BaseEventType{
				Name: "trademark",
				Type: "trademark",
			},
			TrademarkOwner:      owner,
			Country:             country,
			RegistrationNumbers: registrationNumbers,
		}
		event.EventTypes = append(event.EventTypes, trademark)

		result = append(result, event)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
