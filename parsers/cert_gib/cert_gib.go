package cert_gib

import (
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
	// Get body with throws=True (matching Python)
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Convert body to lowercase (matching Python)
	body = strings.ToLower(body)

	// Extract URL: find_string(body, 'hxxp', '\n')
	url := common.FindString(body, "hxxp", "\n")
	url = common.CleanURL(url)
	url = strings.TrimSpace(url)

	// Extract IP: find_string_without_markers(body, 'ip:', ')').replace('[.]', '.')
	ip := common.FindStringWithoutMarkers(body, "ip:", ")")
	ip = strings.ReplaceAll(ip, "[.]", ".")

	// Create event
	event := events.NewEvent("cert_gib")
	event.EventTypes = []events.EventType{events.NewPhishing()}
	event.URL = url
	event.IP = ip

	// Set event_date from email headers['date'][0]
	if serializedEmail.Headers != nil {
		if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
			event.EventDate = email.ParseDate(dateHeader[0])
		}
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
