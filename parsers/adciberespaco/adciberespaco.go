// Package adciberespaco implements the adciberespaco parser
package adciberespaco

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the adciberespaco parser
type Parser struct{}

var (
	eventPattern = regexp.MustCompile(`address\s*(?P<ip>\d+\.\d+\.\d+\.\d+).*(belongs to|associated with) (?P<host_name>.*), is`)
)

// Parse parses emails from @adciberespaco
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Strip HTML tags - simple implementation
	body = stripHTML(body)

	// Extract IP and hostname
	match := eventPattern.FindStringSubmatch(body)
	if match == nil {
		return nil, common.NewParserError("Format changed adapt the parser")
	}

	// Extract named groups
	var ip, hostName string
	for i, name := range eventPattern.SubexpNames() {
		if i > 0 && i < len(match) {
			switch name {
			case "ip":
				ip = match[i]
			case "host_name":
				hostName = match[i]
			}
		}
	}

	// Create event
	event := events.NewEvent("adciberespaco")

	// Get date
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate := email.ParseDate(dateHeaders[0])
		event.EventDate = eventDate
	}

	// Set IP
	if validIP := common.IsIP(ip); validIP != "" {
		event.IP = validIP
	}

	// Add host organization
	host := &events.Organisation{
		Name:         "host",
		Organisation: hostName,
	}
	event.AddEventDetail(host)

	// Add reporter organization
	reporter := &events.Organisation{
		Name:         "reporter",
		Organisation: "ACDE",
	}
	event.AddEventDetail(reporter)

	// Determine event type
	bodyLower := strings.ToLower(body)
	if strings.Contains(bodyLower, "copyright") {
		event.EventTypes = []events.EventType{&events.Copyright{}}
	} else {
		return nil, common.NewNewTypeError("adapt the parser")
	}

	return []*events.Event{event}, nil
}

// stripHTML removes HTML tags from a string
// This is a simplified version - full implementation would use html.Parse
func stripHTML(s string) string {
	// Remove HTML tags
	tagRe := regexp.MustCompile(`<[^>]*>`)
	s = tagRe.ReplaceAllString(s, "")

	// Decode common HTML entities
	s = strings.ReplaceAll(s, "&nbsp;", " ")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&quot;", "\"")

	return s
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
