package themccandlessgroup

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	email "github.com/abusix/inbound-parsers/pkg/email"
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

	// Extract owner information line after the marker
	ownerInformation := common.GetNonEmptyLineAfter(body, "Copyright owner's address / telephone number / email address:")
	ownerInformation = strings.Trim(ownerInformation, "- ")

	// Split owner information by '/'
	parts := strings.Split(ownerInformation, "/")
	if len(parts) != 3 {
		return nil, common.NewParserError("format changed adapt the parser")
	}

	address := strings.TrimSpace(parts[0])
	contactPhone := strings.TrimSpace(parts[1])
	organisationEmail := strings.TrimSpace(parts[2])

	// Create the copyright owner organisation
	owner := &events.Organisation{
		Name:         "copyright_owner",
		Address:      address,
		ContactPhone: contactPhone,
		ContactEmail: organisationEmail,
	}

	// Extract the official work URL
	originalWork := common.FindStringWithoutMarkers(body, "can be found at:", "")

	// Extract all URLs from the block after "material that is infringing"
	urls := common.GetBlockAfterWithStop(body, "material that is infringing", "")

	var eventsList []*events.Event

	for _, urlLine := range urls {
		url := strings.Trim(urlLine, "- ")
		if url != "" {
			event := events.NewEvent("themccandlessgroup")

			// Set event date from email header
			if serializedEmail.Headers != nil {
				if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
					event.AddEventDetailSimple("event_date", dateHeader[0])
				}
			}

			// Set URL
			event.URL = url

			// Create Copyright event type with official URL
			copyrightEvent := &events.Copyright{
				BaseEventType: events.BaseEventType{
					Name: "copyright",
					Type: "copyright",
				},
				OfficialURL: originalWork,
			}
			event.EventTypes = []events.EventType{copyrightEvent}

			// Add the copyright owner as event detail
			event.AddEventDetail(owner)

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
