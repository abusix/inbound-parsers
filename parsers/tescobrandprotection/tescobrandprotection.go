package tescobrandprotection

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
	// Get body and subject (throws error if not available)
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Convert to lowercase for case-insensitive matching
	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)

	// Create event template
	eventTemplate := events.NewEvent("tescobrandprotection")

	// Set event date from headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate := email.ParseDate(dateHeaders[0])
		eventTemplate.EventDate = eventDate
	}

	// Set trademark event type
	trademark := &events.Trademark{
		BaseEventType: events.BaseEventType{
			Name: "trademark",
			Type: "trademark",
		},
		TrademarkOwner: "Tesco Stores Limited",
	}
	eventTemplate.EventTypes = []events.EventType{trademark}

	// Extract external ID from subject (format: "[ECIN: 12345]")
	externalID := common.FindStringWithoutMarkers(subjectLower, "[ecin:", "]")
	externalID = strings.TrimSpace(externalID)
	if externalID != "" {
		eventTemplate.AddEventDetail(&events.ExternalID{ID: externalID})
	}

	// Parse URLs based on body format
	var urlBlock []string

	if strings.Contains(bodyLower, "the infringing material at the following url(s):") {
		// Format 1: URLs after "the infringing material at the following url(s):"
		urlBlock = common.GetBlockAfterWithStop(bodyLower, "the infringing material at the following url(s):", "")
	} else if strings.Contains(bodyLower, "on your website available at:") {
		// Format 2: URLs between "on your website available at:" and "infringement of tesco's rights"
		urlText := common.FindStringWithoutMarkers(
			bodyLower,
			"on your website available at:",
			"infringement of tesco's rights",
		)
		urlBlock = strings.Split(urlText, "\n")
	} else {
		// Format 3: URL from subject (between "notice of infringement" and "[ecin:")
		url := common.FindStringWithoutMarkers(
			subjectLower,
			"notice of infringement",
			"[ecin:",
		)
		url = strings.TrimSpace(url)
		if url != "" {
			event := events.NewEvent("tescobrandprotection")
			event.URL = url
			event.EventDate = eventTemplate.EventDate
			event.EventTypes = eventTemplate.EventTypes
			if externalID != "" {
				event.AddEventDetail(&events.ExternalID{ID: externalID})
			}
			return []*events.Event{event}, nil
		}
		return nil, common.NewParserError("no URLs found in subject or body")
	}

	// Create events from URL block
	return parseURLBlock(urlBlock, eventTemplate), nil
}

// parseURLBlock creates events for each URL in the block
func parseURLBlock(urlBlock []string, eventTemplate *events.Event) []*events.Event {
	var eventsList []*events.Event

	for _, line := range urlBlock {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Check if line is a URL
		if !common.IsURL(line) {
			continue
		}

		// Create a copy of the event template for this URL
		event := events.NewEvent(eventTemplate.Parser)
		event.URL = line
		event.EventDate = eventTemplate.EventDate
		event.EventTypes = eventTemplate.EventTypes

		// Copy event details (external ID)
		if len(eventTemplate.EventDetails) > 0 {
			event.EventDetails = make([]events.EventDetail, len(eventTemplate.EventDetails))
			copy(event.EventDetails, eventTemplate.EventDetails)
		}

		eventsList = append(eventsList, event)
	}

	return eventsList
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
