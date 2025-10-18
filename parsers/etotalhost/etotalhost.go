// Package etotalhost implements the etotalhost parser
package etotalhost

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the etotalhost parser
type Parser struct{}

// parseWebHack parses web hack reports
func parseWebHack(body string) *events.Event {
	event := events.NewEvent("etotalhost")
	event.EventTypes = []events.EventType{events.NewWebHack()}
	event.IP = common.FindStringWithoutMarkers(body, "client ip:", "")

	targetIP := common.FindStringWithoutMarkers(body, "server ip:", "")
	targetPort := common.FindStringWithoutMarkers(body, "server port: ", "")
	targetURL := common.FindStringWithoutMarkers(body, "server name: ", "")

	if targetIP != "" || targetPort != "" || targetURL != "" {
		target := &events.Target{
			IP:   targetIP,
			Port: targetPort,
			URL:  targetURL,
		}
		event.AddEventDetail(target)
	}

	dateStr := common.FindStringWithoutMarkers(body, "server time: ", "")
	event.EventDate = email.ParseDate(dateStr)

	return event
}

// parseSpamAndFraud parses spam and fraud reports
func parseSpamAndFraud(serializedEmail *email.SerializedEmail, body string, eventType events.EventType) *events.Event {
	event := events.NewEvent("etotalhost")
	event.EventTypes = []events.EventType{eventType}
	event.IP = common.FindStringWithoutMarkers(body, "originating ip: ", "")

	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	return event
}

// Parse parses emails from @etotalhost for web hack, spam, and fraud reports
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	bodyLower := strings.ToLower(body)

	var event *events.Event

	if strings.Contains(subjectLower, "abuse report for") {
		event = parseWebHack(bodyLower)
	} else if strings.Contains(subjectLower, "forwarded spam email") {
		event = parseSpamAndFraud(serializedEmail, bodyLower, events.NewSpam())
	} else if strings.Contains(subjectLower, "forwarded fraud email") {
		event = parseSpamAndFraud(serializedEmail, bodyLower, events.NewFraud())
	} else {
		return nil, common.NewNewTypeError(subject)
	}

	// Try to add external ID
	if xMailID, ok := serializedEmail.Headers["x-mail-id"]; ok && len(xMailID) > 0 {
		externalID := &events.ExternalID{ID: xMailID[0]}
		event.AddEventDetail(externalID)
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
