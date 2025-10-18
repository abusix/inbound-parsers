package joturl

import (
	"regexp"
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

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Clean subject: lowercase and remove carriage returns
	subject = strings.ToLower(strings.ReplaceAll(subject, "\r\n", ""))

	var eventsList []*events.Event

	// Check if subject contains 'post requests'
	if strings.Contains(subject, "post requests") {
		// Extract IPv4 addresses using regex
		ipv4Regex := regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
		ipv4Matches := ipv4Regex.FindAllString(body, -1)

		// Extract IPv6 addresses using regex
		ipv6Regex := regexp.MustCompile(`\S*:.*:.*:.*:.*:\S*`)
		ipv6Matches := ipv6Regex.FindAllString(body, -1)

		// Create a set to deduplicate IPs
		ipSet := make(map[string]bool)
		for _, ip := range ipv4Matches {
			ipSet[ip] = true
		}
		for _, ip := range ipv6Matches {
			ipSet[ip] = true
		}

		// Get event date from headers
		var eventDate *time.Time
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventDate = email.ParseDate(dateHeaders[0])
		}

		// Create an event for each unique IP
		for ip := range ipSet {
			event := events.NewEvent("joturl")
			event.EventDate = eventDate
			event.IP = ip
			event.EventTypes = []events.EventType{events.NewDDoS()}
			eventsList = append(eventsList, event)
		}
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
