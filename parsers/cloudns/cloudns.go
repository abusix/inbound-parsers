package cloudns

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
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)

	// Check for DDoS attack keywords in subject
	isDDoS := strings.Contains(subjectLower, "dns query flood attack") ||
		strings.Contains(subjectLower, "high volume of dns queries")

	if !isDDoS {
		return nil, &common.NewTypeError{Subject: subjectLower}
	}

	event := events.NewEvent("cloudns")
	event.EventTypes = []events.EventType{events.NewDDoS()}

	// Parse event date from body (format: "YYYY-MM-DD HH:MM:SS number queries")
	datePattern := regexp.MustCompile(`(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \d+ queries`)
	if dateMatch := datePattern.FindStringSubmatch(bodyLower); dateMatch != nil {
		dateStr := dateMatch[1]
		if parsedTime, err := time.Parse("2006-01-02 15:04:05", dateStr); err == nil {
			event.EventDate = &parsedTime
		}
	} else {
		// Fall back to email Date header
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Set IP from subject (the subject contains the IP address)
	event.IP = subjectLower

	// Extract target IP from body
	targetIP := common.FindStringWithoutMarkers(bodyLower, "attacks directed at", "")
	if targetIP != "" {
		event.AddEventDetail(&events.Target{IP: targetIP})
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
