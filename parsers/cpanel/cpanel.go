package cpanel

import (
	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"strings"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	bodyLower := strings.ToLower(body)
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	event := events.NewEvent("cpanel")

	// Determine event type based on body content
	if strings.Contains(bodyLower, "brute-force") || strings.Contains(bodyLower, "attack for") {
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	} else if strings.Contains(bodyLower, "port scan") {
		event.EventTypes = []events.EventType{events.NewPortScan()}
	} else {
		return nil, common.NewNewTypeError(subject)
	}

	// IP is in the subject
	event.IP = subject

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
