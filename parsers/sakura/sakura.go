// Package sakura implements the Sakura parser for spam reports
package sakura

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the Sakura parser
type Parser struct{}

// Parse parses emails from sakura.ne.jp
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get email body
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Extract host information: "URL(IP)"
	hostLine := common.FindStringWithoutMarkers(body, "Host:", "")
	if hostLine == "" {
		return nil, common.NewParserError("Host line not found")
	}

	// Split by '(' to separate URL and IP
	parts := strings.SplitN(hostLine, "(", 2)
	if len(parts) != 2 {
		return nil, common.NewParserError("invalid Host format, expected 'URL(IP)'")
	}

	url := strings.TrimSpace(parts[0])
	ipPart := strings.TrimRight(parts[1], ")")
	ip := common.IsIP(ipPart)
	if ip == "" {
		return nil, common.NewParserError("invalid IP in Host line")
	}

	// Extract date
	dateStr := common.GetNonEmptyLineAfter(body, "Date:")
	if dateStr == "" {
		return nil, common.NewParserError("Date not found")
	}

	// Create event
	event := events.NewEvent("sakura")
	event.EventTypes = []events.EventType{events.NewSpam()}
	event.IP = ip
	event.URL = url
	event.EventDate = email.ParseDate(dateStr)

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
