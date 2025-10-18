package fbs

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
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	// Check if subject contains expected keywords
	subjectLower := strings.ToLower(subject)
	if !strings.Contains(subjectLower, "ddos") && !strings.Contains(subjectLower, "malicious activity") {
		return nil, common.NewNewTypeError(subject)
	}

	var eventsList []*events.Event

	// Find the marker for IP list
	marker := ""
	for _, mark := range []string{"list of IP's:", "list of IPs:"} {
		if strings.Contains(body, mark) {
			marker = mark
			break
		}
	}

	// If marker found, extract IPs from the block after it
	if marker != "" {
		// Add newline after marker to ensure proper parsing
		bodyWithMarker := strings.Replace(body, marker, marker+"\n", 1)

		// Get lines after the marker
		lines := common.GetBlockAfterWithStop(bodyWithMarker, marker, "")

		for _, line := range lines {
			if ip := common.ExtractOneIP(line); ip != "" {
				event := events.NewEvent("fbs")
				event.IP = ip

				// Set event type based on subject
				if strings.Contains(subjectLower, "ddos") {
					event.EventTypes = []events.EventType{events.NewDDoS()}
				} else if strings.Contains(subjectLower, "malicious activity") {
					event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
				}

				// Set event date from email headers
				if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
					event.EventDate = email.ParseDate(dateHeaders[0])
				}

				eventsList = append(eventsList, event)
			}
		}
	}

	// Return error if no events were created
	if len(eventsList) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
