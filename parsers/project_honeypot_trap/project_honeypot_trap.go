package project_honeypot_trap

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

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Check for x-hp-connectip header (required)
	connectIP, ok := serializedEmail.Headers["x-hp-connectip"]
	if !ok || len(connectIP) == 0 {
		return nil, common.NewParserError("Received trap hit from project honeypot with unknown format")
	}

	event := events.NewEvent("project_honeypot_trap")

	// Set IP from x-hp-connectip header
	event.IP = connectIP[0]

	// Set event types to Spam (Python also sets Trap, but that doesn't exist in Go events)
	spam := events.NewSpam()
	event.EventTypes = []events.EventType{spam}

	// Try to get event date from x-hp-received header
	if hpReceived, ok := serializedEmail.Headers["x-hp-received"]; ok && len(hpReceived) > 0 {
		if parsedDate := email.ParseDate(hpReceived[0]); parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	// If no event date yet, fall back to Received headers
	if event.EventDate == nil {
		if received, ok := serializedEmail.Headers["received"]; ok && len(received) > 0 {
			receivedHeader := email.NewReceivedHeader(received)

			// Try index 1 first, then fall back to index 0
			date := receivedHeader.ReceivedDate(1)
			if date == nil {
				date = receivedHeader.ReceivedDate(0)
			}

			if date != nil {
				event.EventDate = date
			}
		}
	}

	// Construct email from x-hp-envfromuser and x-hp-envfromdom headers
	if hasEnvFrom(serializedEmail.Headers) {
		user := ""
		domain := ""

		if envFromUser, ok := serializedEmail.Headers["x-hp-envfromuser"]; ok && len(envFromUser) > 0 {
			user = strings.TrimSpace(envFromUser[0])
		}

		if envFromDom, ok := serializedEmail.Headers["x-hp-envfromdom"]; ok && len(envFromDom) > 0 {
			domain = strings.TrimSpace(envFromDom[0])
		}

		trapHitFrom := ""
		if user == "" {
			trapHitFrom = domain
		} else if domain == "" {
			trapHitFrom = user
		} else {
			trapHitFrom = user + "@" + domain
		}

		if trapHitFrom != "" {
			emailDetail := &events.Email{
				FromAddress: trapHitFrom,
			}
			event.AddEventDetail(emailDetail)
		}
	}

	return []*events.Event{event}, nil
}

// hasEnvFrom checks if either x-hp-envfromuser or x-hp-envfromdom exists
func hasEnvFrom(headers map[string][]string) bool {
	_, hasUser := headers["x-hp-envfromuser"]
	_, hasDom := headers["x-hp-envfromdom"]
	return hasUser || hasDom
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
