// Package redpoints implements the redpoints.com parser
package redpoints

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the redpoints parser
type Parser struct{}

// Parse parses emails from @redpoints.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Get date from headers
	eventDate := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = dateHeaders[0]
	}

	bodyLower := strings.ToLower(body)

	// Check if this is a trademark case
	if strings.Contains(body, "trademark") {
		return parseTrademark(body, bodyLower, eventDate)
	}

	// Otherwise parse as copyright
	return parseCopyright(body, bodyLower, subject, eventDate)
}

func parseTrademark(body, bodyLower, eventDate string) ([]*events.Event, error) {
	eventTemplate := events.NewEvent("redpoints")
	eventTemplate.EventDate = email.ParseDate(eventDate)
	eventTemplate.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}

	// Extract IP if present
	ip := common.FindStringWithoutMarkers(bodyLower, "ip address:", "")
	if ip != "" {
		eventTemplate.IP = strings.TrimSpace(ip)
	}

	// Get URLs block
	urlBlock := common.GetBlockAfterWithStop(body, "URL(s) where illegal content is located:", "")

	var result []*events.Event
	if len(urlBlock) > 0 {
		for _, url := range urlBlock {
			event := &events.Event{
				Parser:       eventTemplate.Parser,
				EventDate:    eventTemplate.EventDate,
				EventTypes:   eventTemplate.EventTypes,
				IP:           eventTemplate.IP,
				URL:          url,
				Headers:      make(map[string]interface{}),
				Requirements: make(map[string]events.Requirement),
			}
			result = append(result, event)
		}
	} else {
		result = append(result, eventTemplate)
	}

	return result, nil
}

func parseCopyright(body, bodyLower, subject, eventDate string) ([]*events.Event, error) {
	event := events.NewEvent("redpoints")
	event.EventDate = email.ParseDate(eventDate)

	// Find URL
	url := common.GetNonEmptyLineAfter(body, "intellectual property rights:")
	if url == "" {
		url = common.GetNonEmptyLineAfter(body, "any further damages to both our client and consumers:")
	}

	if strings.HasPrefix(url, "IP Address:") {
		// New format
		url = common.GetNonEmptyLineAfter(body, "Infringing URLs")
		if url == "" {
			url = common.FindStringWithoutMarkers(body, "Infringing Domain: ", "")
		}
		// Extract IP from new format
		ip := common.FindStringWithoutMarkers(body, "IP Address:", "")
		if strings.TrimSpace(ip) != "" {
			event.IP = strings.TrimSpace(ip)
		}
	}

	if url == "" {
		return nil, common.NewParserError("No url found")
	}
	event.URL = url

	// Extract copyright owner
	copyrightOwner := common.FindStringWithoutMarkers(body, "of our client", ",")
	copyrightOwner = strings.ReplaceAll(copyrightOwner, "\n", "")
	copyrightOwner = strings.ReplaceAll(copyrightOwner, "\r", "")

	// Extract copyrighted work and official URL
	copyrightedWorkLine := common.GetNonEmptyLineAfter(body, "copyrighted work(s)")
	copyrightedWorkLine = strings.ReplaceAll(copyrightedWorkLine, ")", "")

	copyrightedWork := ""
	officialURL := ""
	if parts := strings.SplitN(copyrightedWorkLine, "(", 2); len(parts) > 0 {
		copyrightedWork = strings.TrimSpace(parts[0])
		if len(parts) > 1 {
			officialURL = strings.TrimSpace(parts[1])
		}
	}

	// Create Copyright event type
	copyright := &events.Copyright{
		BaseEventType: events.BaseEventType{
			Name: "copyright",
			Type: "copyright",
		},
		CopyrightOwner:  strings.TrimSpace(copyrightOwner),
		CopyrightedWork: copyrightedWork,
		OfficialURL:     officialURL,
	}

	event.EventTypes = []events.EventType{copyright}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
