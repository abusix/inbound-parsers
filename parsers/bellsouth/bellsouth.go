package bellsouth

import (
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

	event := events.NewEvent("bellsouth")
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Set event date from email headers
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Try to extract a more specific date from body
	// Pattern: Mon, 02 Jan 2006 15:04:05 +0700
	datePattern := regexp.MustCompile(`\w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2} (\+|-)\d{4}`)
	if dateMatch := datePattern.FindString(body); dateMatch != "" {
		if parsedDate := email.ParseDate(dateMatch); parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	// Extract IP from X-Originating-Ip field
	event.IP = strings.TrimSpace(common.FindStringWithoutMarkers(body, "X-Originating-Ip:", "\n"))

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
