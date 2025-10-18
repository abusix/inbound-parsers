package gmx

import (
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// getIPFromBody extracts IP address from email body
func getIPFromBody(body string) string {
	// Try first pattern: "ip: "
	ip := common.FindStringWithoutMarkers(body, "ip: ", "")
	if ip != "" {
		return ip
	}

	// Try second pattern: between "mailspamming from ip" and "for further detail"
	ip = common.FindStringWithoutMarkers(body, "mailspamming from ip", "for further detail")
	return ip
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get body and convert to lowercase
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	body = strings.ToLower(body)

	// Get event date from headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	// Extract IP from body
	sourceIP := getIPFromBody(body)

	// Create event
	event := events.NewEvent("gmx")
	event.EventDate = eventDate
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Set IP if found
	if sourceIP != "" {
		if validIP := common.IsIP(sourceIP); validIP != "" {
			event.IP = validIP
		}
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
