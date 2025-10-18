package copyright_integrity

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

	// Extract IP address
	ip := common.FindStringWithoutMarkers(body, "IP address:", "")

	// Extract URL - get first non-empty line after "following URL"
	url := common.GetNonEmptyLineAfter(body, "following URL")

	// Extract case reference
	caseRef := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Case Ref:", ""))

	// Extract copyright owner - get text between markers and join lines
	ownerRaw := common.FindStringWithoutMarkers(body, "Exclusive Rights have been granted to ", "(")
	ownerLines := strings.Split(ownerRaw, "\n")
	var ownerParts []string
	for _, line := range ownerLines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			ownerParts = append(ownerParts, trimmed)
		}
	}
	owner := strings.TrimSpace(strings.Join(ownerParts, " "))

	// Create event
	event := events.NewEvent("copyright_integrity")

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Set event type with copyright owner
	event.EventTypes = []events.EventType{
		events.NewCopyright("", owner, ""),
	}

	// Set IP and URL
	event.IP = ip
	event.URL = url

	// Add external ID (case reference)
	if caseRef != "" {
		event.AddEventDetail(&events.ExternalID{ID: caseRef})
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
