package rediffmail_tis

import (
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Ensure we have parts to work with
	if len(serializedEmail.Parts) == 0 {
		return nil, common.NewParserError("No email parts found")
	}

	// Get evidence headers from the first part
	evidenceHeaders := serializedEmail.Parts[0].Headers
	if evidenceHeaders == nil {
		return nil, common.NewParserError("No headers found in first part")
	}

	// Determine which header contains the IP information
	var declaredIPs []string
	if remoteIP, exists := evidenceHeaders["x-remote-ip"]; exists && len(remoteIP) > 0 {
		declaredIPs = remoteIP
	} else if spfVerification, exists := evidenceHeaders["x-spf-verification"]; exists && len(spfVerification) > 0 {
		declaredIPs = spfVerification
	} else if originatingIP, exists := evidenceHeaders["x-originating-ip"]; exists && len(originatingIP) > 0 {
		declaredIPs = originatingIP
	} else {
		return nil, common.NewParserError("No header present that indicates the correct event ip")
	}

	var eventList []*events.Event

	// Create an event for each IP
	for _, singleIP := range declaredIPs {
		event := events.NewEvent("rediffmail_tis")
		event.EventTypes = []events.EventType{events.NewSpam()}
		event.IP = singleIP

		// Try to get event date from Date header
		if dateHeaders, exists := evidenceHeaders["date"]; exists && len(dateHeaders) > 0 {
			eventDate := email.ParseDate(dateHeaders[0])
			if eventDate != nil {
				event.EventDate = eventDate
			}
		}

		// Fallback to Received header if date not set
		if event.EventDate == nil {
			if receivedHeaders, exists := evidenceHeaders["received"]; exists && len(receivedHeaders) > 0 {
				parsedReceived := email.NewReceivedHeader(receivedHeaders)
				eventDate := parsedReceived.ReceivedDate(0)
				if eventDate != nil {
					event.EventDate = eventDate
				}
			}
		}

		// Last resort: use report date from main headers
		if event.EventDate == nil {
			if dateHeaders, exists := serializedEmail.Headers["date"]; exists && len(dateHeaders) > 0 {
				eventDate := email.ParseDate(dateHeaders[0])
				if eventDate != nil {
					event.EventDate = eventDate
				}
			}
		}

		eventList = append(eventList, event)
	}

	return eventList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
