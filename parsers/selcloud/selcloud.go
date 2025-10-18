package selcloud

import (
	"fmt"
	"regexp"
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

	if !strings.Contains(body, "BRUTE-FORCE") {
		return nil, fmt.Errorf("new type: %s", subject)
	}

	event := events.NewEvent("selcloud")
	event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

	// Get the event line after "We attached some logs:"
	eventLine := common.GetNonEmptyLineAfter(body, "We attached some logs:")
	if eventLine == "" {
		return nil, fmt.Errorf("could not find event line after 'We attached some logs:'")
	}

	// Extract IP address (the line itself is the IP)
	event.IP = eventLine

	// Extract event date using regex pattern: YYYY-MM-DD HH:MM:SS
	datePattern := regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}`)
	dateMatch := datePattern.FindString(eventLine)
	if dateMatch == "" {
		return nil, fmt.Errorf("could not extract date from event line: %s", eventLine)
	}

	// Parse the date
	eventDate := email.ParseDate(dateMatch)
	if eventDate == nil {
		return nil, fmt.Errorf("failed to parse date: %s", dateMatch)
	}
	event.EventDate = eventDate

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
