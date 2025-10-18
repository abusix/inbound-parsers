// Package ibm implements the IBM parser
package ibm

import (
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the IBM parser
type Parser struct{}

// Parse parses emails from @us.ibm.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Process subject: lowercase and replace "ibm's" with "ibm"
	subjectLower := strings.ToLower(subject)
	subjectLower = strings.ReplaceAll(subjectLower, "ibm's", "ibm")

	// Get event date from headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	// Parse based on subject content
	if strings.Contains(subjectLower, "misuse of ibm trademark") {
		return parseTrademark(body, eventDate)
	} else if strings.Contains(subjectLower, "fraudulent activity") {
		return parseFraud(subjectLower, eventDate)
	} else if strings.Contains(subjectLower, "improper use originating from your network") {
		return parseLoginAttack(body, eventDate)
	} else if strings.Contains(body, "I am receiving SPAM") {
		return parseSpam(body, eventDate)
	}

	return nil, common.NewNewTypeError(subjectLower)
}

func parseTrademark(body string, eventDate *time.Time) ([]*events.Event, error) {
	event := events.NewEvent("ibm")
	event.EventDate = eventDate

	// Set event type - Trademark with owner and material
	trademark := &events.Trademark{
		BaseEventType: events.BaseEventType{
			Name: "trademark",
			Type: "trademark",
		},
		TrademarkOwner:      "ibm",
		TrademarkedMaterial: "ibm",
	}
	event.EventTypes = []events.EventType{trademark}

	// Extract URL from body between markers
	url := common.FindStringWithoutMarkers(
		body,
		"unauthorized registration of a domain name",
		"containing",
	)
	event.URL = url

	return []*events.Event{event}, nil
}

func parseFraud(subjectLower string, eventDate *time.Time) ([]*events.Event, error) {
	event := events.NewEvent("ibm")
	event.EventDate = eventDate
	event.EventTypes = []events.EventType{events.NewFraud()}
	event.IP = subjectLower

	return []*events.Event{event}, nil
}

func parseLoginAttack(body string, eventDate *time.Time) ([]*events.Event, error) {
	event := events.NewEvent("ibm")
	event.EventDate = eventDate
	event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

	// Extract IP from body between markers
	ip := common.FindStringWithoutMarkers(
		body,
		"from your network address",
		"today",
	)
	event.IP = ip

	return []*events.Event{event}, nil
}

func parseSpam(body string, eventDate *time.Time) ([]*events.Event, error) {
	event := events.NewEvent("ibm")
	event.EventDate = eventDate
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Extract IP from body between parentheses
	ip := common.FindStringWithoutMarkers(body, "(", ")")
	event.IP = ip

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
