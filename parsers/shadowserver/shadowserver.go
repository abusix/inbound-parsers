package shadowserver

import (
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/parsers/common"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	event := events.NewEvent("shadowserver")
	event.EventTypes = []events.EventType{events.NewMalware("")}

	// TODO: Port parsing logic from Python version
	_ = body
	_ = subject

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
