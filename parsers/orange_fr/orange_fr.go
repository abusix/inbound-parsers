package orange_fr

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

// parseIP extracts the first IPv4 address from the body
// Assumes the first encountered IP is the reported spammer IP
func parseIP(body string) string {
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		if ip := common.ExtractOneIP(line); ip != "" {
			return ip
		}
	}
	return ""
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	body = strings.ToLower(body)

	event := events.NewEvent("orange_fr")

	// Set event date from email headers
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Set event type to spam
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Extract IP address from body
	event.IP = parseIP(body)

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
