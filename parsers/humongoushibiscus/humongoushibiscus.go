package humongoushibiscus

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
	body, _ := common.GetBody(serializedEmail, false)
	bodyLower := strings.ToLower(body)

	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	// Check if this is a forwarded message
	if !strings.Contains(bodyLower, "- forwarded message -") {
		return nil, common.NewNewTypeError(subjectLower)
	}

	event := events.NewEvent("humongoushibiscus")
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Extract received block: "Received: from" to ";"
	receivedBlock := common.FindString(bodyLower, "received: from", ";")

	// Extract to_address from received block: "for <" to ">"
	toAddress := common.FindStringWithoutMarkers(receivedBlock, "for <", ">")

	// Extract from_address from body: "return-path: <" to ">"
	fromAddress := common.FindStringWithoutMarkers(bodyLower, "return-path: <", ">")

	// Add email detail
	event.AddEventDetail(&events.Email{
		FromAddress: fromAddress,
		ToAddress:   toAddress,
	})

	// Extract IP from received block
	event.IP = common.ExtractOneIP(receivedBlock)

	// Extract event date - this is after the received block
	eventDateStr := common.FindStringWithoutMarkers(bodyLower, receivedBlock, "")
	if eventDateStr != "" {
		eventDateStr = strings.TrimSpace(eventDateStr)
		// Store as string in headers since we don't have date parsing
		if event.Headers == nil {
			event.Headers = make(map[string]interface{})
		}
		event.Headers["event_date_str"] = eventDateStr
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
