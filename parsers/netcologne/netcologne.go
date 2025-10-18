// Package netcologne implements the NetCologne parser for SSH event reports
package netcologne

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the NetCologne parser
type Parser struct{}

// Parse parses emails from spamtrap@netcologne.de
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)

	if strings.Contains(subjectLower, "ssh-event") {
		return parseLoginAttack(body)
	}

	return nil, common.NewNewTypeError(subjectLower)
}

func parseLoginAttack(body string) ([]*events.Event, error) {
	event := events.NewEvent("netcologne")
	event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

	// Extract IP address
	event.IP = common.ExtractOneIP(body)

	// Extract datetime using pattern: YYYY-MM-DD HH:MM:SS
	datetimePattern := regexp.MustCompile(`\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}`)
	dateMatch := datetimePattern.FindString(body)
	if dateMatch != "" {
		event.EventDate = email.ParseDate(dateMatch)
		return []*events.Event{event}, nil
	}

	return nil, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
