// Package ebs implements the ebs parser
package ebs

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the ebs parser
type Parser struct{}

// Parse parses emails for ebs child abuse and illegal advertisement reports
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	bodyLower := strings.ToLower(body)

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	// Determine event type
	var eventType events.EventType
	if strings.Contains(subjectLower, "child sexual") || strings.Contains(subjectLower, "juvenile sexual") {
		eventType = events.NewChildAbuse()
	} else if strings.Contains(subjectLower, "gambling") || strings.Contains(subjectLower, "gamgling") {
		eventType = events.NewIllegalAdvertisement()
	} else if strings.Contains(subjectLower, "animal pornography") || strings.Contains(subjectLower, "animal poronoraphy") {
		eventType = events.NewIllegalAdvertisement()
	} else {
		return nil, common.NewNewTypeError(subject)
	}

	// Extract URL and IP
	url := ""
	urlLine := common.GetNonEmptyLineAfter(bodyLower, "following urls")
	if urlLine != "" {
		parts := strings.Split(urlLine, " ")
		if len(parts) > 0 {
			url = parts[0]
		}
	}

	ip := common.FindStringWithoutMarkers(bodyLower, "ip:", "")
	ip = strings.TrimSpace(ip)

	event := events.NewEvent("ebs")
	event.URL = url
	event.IP = ip
	event.EventTypes = []events.EventType{eventType}

	// Parse event date
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
