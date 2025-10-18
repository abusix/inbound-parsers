// Package etoolkit implements the etoolkit parser
package etoolkit

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the etoolkit parser
type Parser struct{}

// Parse parses emails from @etoolkit for copyright, bot, and malware reports
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	event := events.NewEvent("etoolkit")
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}
	event.IP = subjectLower

	if strings.Contains(subjectLower, "copyright") {
		event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}
	} else if strings.Contains(subjectLower, "bot-infection") {
		event.EventTypes = []events.EventType{events.NewBot("")}
	} else if strings.Contains(subjectLower, "malware") {
		event.EventTypes = []events.EventType{events.NewMalware("")}
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
