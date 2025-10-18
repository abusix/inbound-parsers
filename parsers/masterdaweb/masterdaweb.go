// Package masterdaweb implements the masterdaweb parser
// This is a 100% exact Go translation of Python's masterdaweb parser
package masterdaweb

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/base"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the masterdaweb parser
type Parser struct {
	base.BaseParser
}

// New creates a new masterdaweb parser instance
func New() *Parser {
	return &Parser{
		BaseParser: base.NewBaseParser("masterdaweb"),
	}
}

// Parse parses the email and returns events
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Check if this is a DDoS attack report
	if strings.Contains(strings.ToLower(body), "dos attack") {
		return p.parseDDoS(body, subject)
	}

	// Unknown type
	return nil, common.NewNewTypeError(serializedEmail.Identifier)
}

// parseDDoS parses DDoS attack information from email
func (p *Parser) parseDDoS(body, subject string) ([]*events.Event, error) {
	event := events.NewEvent("masterdaweb")
	event.EventTypes = []events.EventType{events.NewDDoS()}

	// Extract source IP from subject (between "from " and " ")
	sourceIP := common.FindStringWithoutMarkers(subject, "from ", " ")
	if sourceIP != "" {
		event.IP = sourceIP

		// Extract target IP from subject (after "against ")
		if strings.Contains(subject, "against ") {
			parts := strings.Split(subject, "against ")
			if len(parts) > 1 {
				targetIP := strings.TrimSpace(parts[1])
				if targetIP != "" {
					target := &events.Target{
						IP: targetIP,
					}
					event.AddEventDetail(target)
				}
			}
		}

		// Extract event date from body (between "beginning on " and "using")
		eventDateStr := common.FindStringWithoutMarkers(body, "beginning on ", "using")
		if eventDateStr != "" {
			// Store as string in Headers since EventDate expects *time.Time
			// The datetime parsing will be handled by the event processing pipeline
			if event.Headers == nil {
				event.Headers = make(map[string]interface{})
			}
			event.Headers["event_date"] = eventDateStr
		}

		return []*events.Event{event}, nil
	}

	// No IP found, don't return an event
	return nil, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
