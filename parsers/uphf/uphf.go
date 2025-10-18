package uphf

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
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("no email body found")
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil || subject == "" {
		return nil, common.NewParserError("no email subject found")
	}

	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)

	// Check if subject contains "fwd:"
	if !strings.Contains(subjectLower, "fwd:") {
		return nil, common.NewNewTypeError(subjectLower)
	}

	event := events.NewEvent("uphf")
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Extract received block to get event date
	receivedBlock := common.FindString(bodyLower, "received: from", ";")
	if receivedBlock != "" {
		eventDateStr := common.FindStringWithoutMarkers(bodyLower, receivedBlock, "")
		if eventDateStr != "" {
			parsedDate := email.ParseDate(eventDateStr)
			if parsedDate != nil {
				event.EventDate = parsedDate
			}
		}
	}

	// Extract IP from x-original-source-ip header
	ip := common.FindStringWithoutMarkers(bodyLower, "x-original-source-ip:", "")
	event.IP = strings.TrimSpace(ip)

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
