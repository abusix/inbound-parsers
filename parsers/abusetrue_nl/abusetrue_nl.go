// Package abusetrue_nl implements the abuse.true.nl parser
package abusetrue_nl

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the abuse.true.nl parser
type Parser struct{}

var (
	datePattern = regexp.MustCompile(`(?i)(?P<date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2})\s*This IP participated`)
)

// Parse parses emails from abuse@abuse.true.nl
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	// Get date fallback
	dateFallback := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateFallback = dateHeaders[0]
	}

	if strings.Contains(subjectLower, "abuse report") {
		return parseAbuseDDoS(body, subjectLower, dateFallback)
	}

	return nil, common.NewNewTypeError(subjectLower)
}

func parseAbuseDDoS(body, subject, dateFallback string) ([]*events.Event, error) {
	event := events.NewEvent("abusetrue_nl")

	if !strings.Contains(body, "ddos") {
		return nil, common.NewParserError("no ddos found in body")
	}

	// Set event type
	event.EventTypes = []events.EventType{events.NewDDoS()}

	// Find URL target
	if url := findURLTarget(body); url != "" {
		event.AddEventDetail(&events.Target{URL: url})
	}

	// Try to extract IP from subject
	ip := common.IsIP(subject)
	if ip != "" {
		event.IP = ip
	}

	// Extract date from body
	if match := datePattern.FindStringSubmatch(body); len(match) > 1 {
		eventDate := email.ParseDate(match[1])
		event.EventDate = eventDate
	} else {
		eventDate := email.ParseDate(dateFallback)
		event.EventDate = eventDate
	}

	return []*events.Event{event}, nil
}

func findURLTarget(body string) string {
	marker := "ddos flood on"
	endMarker := "ipv4"

	startIdx := strings.Index(body, marker)
	if startIdx == -1 {
		return ""
	}

	remaining := body[startIdx+len(marker):]
	endIdx := strings.Index(remaining, endMarker)
	if endIdx == -1 {
		return ""
	}

	url := strings.TrimSpace(remaining[:endIdx])

	// Handle multiple http occurrences
	if strings.Count(url, "http") > 1 {
		parts := strings.Split(url, "http")
		if len(parts) > 2 {
			url = "http" + parts[2]
		}
	}

	return url
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
