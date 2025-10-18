// Package acastano implements the acastano.fr parser
package acastano

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the acastano parser
type Parser struct{}

var (
	hostnamePattern = regexp.MustCompile(`(?i)(h[^.]*os[^.]*tname )(?P<hostname>\S*)`)
)

// Parse parses emails from @acastano.fr
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Get date fallback
	dateFallback := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateFallback = dateHeaders[0]
	}

	if strings.Contains(subject, "malicious") {
		return parseMalicious(body, subject, dateFallback)
	}

	return nil, common.NewNewTypeError(subject)
}

func parseMalicious(body, subject, dateFallback string) ([]*events.Event, error) {
	event := events.NewEvent("acastano")

	// Set event date
	eventDate := email.ParseDate(dateFallback)
	event.EventDate = eventDate

	// Set event type
	event.EventTypes = []events.EventType{events.NewMaliciousActivity()}

	// Extract IP from subject
	ip := common.ExtractOneIP(subject)
	if ip == "" {
		return nil, common.NewParserError("No IP found in acastano parser")
	}
	event.IP = ip

	// Extract hostname if present
	if match := hostnamePattern.FindStringSubmatch(body); len(match) > 2 {
		hostname := match[2]
		host := &events.Organisation{
			Name:         "host",
			Organisation: hostname,
		}
		event.AddEventDetail(host)
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
