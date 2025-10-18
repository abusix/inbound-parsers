package antipiracy

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

	subject, _ := common.GetSubject(serializedEmail, false)

	// Check if 'copyright' is in the body
	if !strings.Contains(strings.ToLower(body), "copyright") {
		return nil, common.NewParserError("unknown email type: " + subject)
	}

	event := events.NewEvent("antipiracy")
	event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}

	// Get date from headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		event.EventDate = email.ParseDate(dateHeader[0])
	}

	// Extract IP from line after "may be accessed is as follows:"
	ipLines := common.GetBlockAfterWithStop(body, "may be accessed is as follows:", "")
	if len(ipLines) > 0 {
		// Get first non-empty line
		for _, line := range ipLines {
			line = strings.TrimSpace(line)
			if line != "" {
				event.IP = line
				break
			}
		}
	}

	// Extract Case # as external ID
	caseNum := common.FindStringWithoutMarkers(body, "Case #:", "")
	caseNum = strings.TrimSpace(caseNum)
	if caseNum != "" {
		event.AddEventDetail(&events.ExternalID{ID: caseNum})
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
