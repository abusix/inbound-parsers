package timbrasil

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
	subject, _ := common.GetSubject(serializedEmail, false)

	event := events.NewEvent("timbrasil")

	// Extract type string from body after "Activities of"
	typeString := strings.ToLower(common.FindStringWithoutMarkers(body, "Activities of", ""))

	// Extract IP from subject, replacing _ with .
	ip := common.ExtractOneIP(strings.ReplaceAll(subject, "_", "."))

	// Determine event type based on type string
	if strings.Contains(typeString, "port scan") {
		event.EventTypes = []events.EventType{events.NewPortScan()}
	} else if strings.Contains(typeString, "brute force") || strings.Contains(typeString, "intrusion attempt") {
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	} else if strings.Contains(typeString, "waf") {
		event.EventTypes = []events.EventType{events.NewCompromisedServer()}
	} else if typeString == "" && strings.Contains(body, "compromised") {
		event.EventTypes = []events.EventType{events.NewCompromisedServer()}
	} else {
		return nil, common.NewNewTypeError(typeString)
	}

	event.IP = ip

	// Set event date from email date header
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
