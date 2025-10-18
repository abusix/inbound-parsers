package ukie

import (
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

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)

	// Check if this is a copyright infringement notice
	if !strings.Contains(subjectLower, "notice of copyright infringement") {
		return nil, common.NewNewTypeError(subjectLower)
	}

	// Create event template
	eventTemplate := events.NewEvent("ukie")
	eventTemplate.EventTypes = []events.EventType{events.NewCopyright("", "", "")}

	// Set event date from email headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventTemplate.EventDate = email.ParseDate(dateHeader[0])
	}

	// Extract external ID (reference number)
	externalID := common.FindStringWithoutMarkers(body, "(Our Ref:", ")")
	externalID = strings.TrimSpace(externalID)
	if externalID != "" {
		eventTemplate.AddEventDetail(&events.ExternalID{ID: externalID})
	}

	// Extract URL block after the marker text
	urlBlock := common.GetBlockAfter(body, "The following URL(s) identify the infringing files and the means to locate them.")

	// Create one event per URL
	var results []*events.Event
	for _, url := range urlBlock {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}

		// Create a copy of the event template for each URL
		eventCopy := *eventTemplate
		eventCopy.URL = url

		// Copy EventDetails slice to avoid sharing
		if len(eventTemplate.EventDetails) > 0 {
			eventCopy.EventDetails = make([]events.EventDetail, len(eventTemplate.EventDetails))
			copy(eventCopy.EventDetails, eventTemplate.EventDetails)
		}

		results = append(results, &eventCopy)
	}

	if len(results) == 0 {
		return nil, common.NewParserError("no URLs found in email")
	}

	return results, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
