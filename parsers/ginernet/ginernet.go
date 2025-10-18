// Package ginernet implements the ginernet.com parser
package ginernet

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the ginernet parser
type Parser struct{}

// Parse parses emails from soporte@ginernet.com
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

	if strings.Contains(subjectLower, "blacklist") {
		return parseBlacklist(serializedEmail, body)
	}

	return nil, common.NewNewTypeError(subject)
}

func parseBlacklist(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	event := events.NewEvent("ginernet")

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate := email.ParseDate(dateHeaders[0])
		event.EventDate = eventDate
	}

	// Extract IP address
	ip := common.FindStringWithoutMarkers(body, "IP:", "")
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil, common.NewParserError("No IP found in ginernet parser")
	}
	event.IP = ip

	// Extract blacklist name
	blacklistName := common.FindStringWithoutMarkers(body, "Blacklist:", "")
	blacklistName = strings.TrimSpace(blacklistName)

	// Set event type to Blacklist
	event.EventTypes = []events.EventType{events.NewBlacklist(blacklistName)}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
