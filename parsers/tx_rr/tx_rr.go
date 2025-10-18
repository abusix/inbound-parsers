package tx_rr

import (
	"fmt"
	"strings"

	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Check if 'spam' is in subject (case-insensitive)
	if !strings.Contains(strings.ToLower(subject), "spam") {
		return nil, fmt.Errorf("unexpected subject type: %s", subject)
	}

	// Extract the URL using get_non_empty_line_after
	url := common.GetNonEmptyLineAfter(strings.ToLower(body), "offending url")

	event := events.NewEvent("tx_rr")
	event.URL = url
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Set event_date from the Date header
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
