// Package pccc_trap implements the pccc_trap parser
// This is a 100% exact Go translation of Python's pccc_trap parser
package pccc_trap

import (
	"fmt"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the pccc_trap parser
type Parser struct{}

// NewParser creates a new pccc_trap parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from pccc.com spam trap
// Python equivalent: parsers/parser/pccc_trap.py
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	event := events.NewEvent("pccc_trap")

	// Set event types: Spam and Trap (trap is a subtype of spam)
	spam := events.NewSpam()
	event.EventTypes = []events.EventType{spam}

	// Get received headers
	received, ok := serializedEmail.Headers["received"]
	if !ok || len(received) == 0 {
		return nil, fmt.Errorf("no received headers found")
	}

	// Find significant headers containing 'pccc.com'
	var significantHeaders []string
	for _, header := range received {
		if strings.Contains(header, "pccc.com") {
			significantHeaders = append(significantHeaders, header)
		}
	}

	// If no pccc headers found, use the second received header as default
	// (first outside our systems), or first header if only one exists
	if len(significantHeaders) == 0 {
		if len(received) > 1 {
			significantHeaders = []string{received[1]}
		} else {
			significantHeaders = []string{received[0]}
		}
	}

	// Try to find the first valid IP from significant headers (reversed)
	// In some rare cases their messages go through multiple relays
	var lastError error
	for i := len(significantHeaders) - 1; i >= 0; i-- {
		header := significantHeaders[i]
		ip := common.ExtractOneIP(header)

		if ip != "" {
			event.IP = ip

			// Try to extract the received date from this header
			// Format: "from ... by ... ; Thu, 18 Oct 2025 01:00:00 +0000"
			if idx := strings.LastIndex(header, ";"); idx != -1 {
				dateStr := strings.TrimSpace(header[idx+1:])
				if parsedDate := email.ParseDate(dateStr); parsedDate != nil {
					event.EventDate = parsedDate
				}
			}
			break
		}
	}

	// If no IP found, return error
	if event.IP == "" {
		if lastError != nil {
			return nil, lastError
		}
		return nil, fmt.Errorf("could not determine any valid IP from Received headers")
	}

	// Add envelope_from as email event detail if present
	if serializedEmail.Metadata.EnvelopeFrom != "" {
		emailDetail := &events.Email{
			FromAddress: serializedEmail.Metadata.EnvelopeFrom,
		}
		event.AddEventDetail(emailDetail)
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
