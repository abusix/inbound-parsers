package cert_rcts

import (
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

	event := events.NewEvent("cert_rcts")
	event.EventTypes = []events.EventType{events.NewExploit()}

	// Remove carriage returns from body
	body = common.RemoveCarriageReturn(body)

	// Extract source IP
	event.IP = common.FindStringWithoutMarkers(body, "Source IP: ", " ")

	// Extract destination IP and port for Target
	destinationIP := common.FindStringWithoutMarkers(body, "Destination IP: ", "")
	destinationPort := common.FindStringWithoutMarkers(body, "Destination port: ", "")
	target := &events.Target{
		IP:   destinationIP,
		Port: destinationPort,
	}

	// Extract payload for Sample
	payload := common.FindStringWithoutMarkers(body, "Payload: ", " ")
	sample := &events.Sample{
		Payload: payload,
	}

	event.AddEventDetail(sample)
	event.AddEventDetail(target)

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
