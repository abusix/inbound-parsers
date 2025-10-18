package hack_hunt

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
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)

	// Extract infringing URL
	url := common.GetNonEmptyLineAfter(bodyLower, "infringing content can be found at:")

	// Extract official URL
	officialURL := common.GetNonEmptyLineAfter(bodyLower, "original work at:")

	// Create event
	event := events.NewEvent("hack_hunt")

	// Set event date from email headers
	dateStr := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateStr = dateHeaders[0]
	}
	event.EventDate = email.ParseDate(dateStr)

	// Set URL
	event.URL = url

	// Set event type as Copyright with official URL
	copyright := events.NewCopyright("", "", "")
	copyright.OfficialURL = officialURL
	event.EventTypes = []events.EventType{copyright}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
