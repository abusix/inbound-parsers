// Package laliga implements the laliga parser
// This is a 100% exact Go translation of Python's laliga.py
package laliga

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/base"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the laliga parser
type Parser struct {
	base.BaseParser
}

// New creates a new laliga parser instance
func New() *Parser {
	return &Parser{
		BaseParser: base.NewBaseParser("laliga"),
	}
}

// Parse parses emails from @laliga.report
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)

	if strings.Contains(subjectLower, "intellectual property violation") {
		// Extract IP address
		ip := common.FindStringWithoutMarkers(body, "IP address", ":")
		ip = strings.TrimSpace(ip)

		// Get event date from headers
		var eventDate *string
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventDate = &dateHeaders[0]
		}

		// Extract URL block after the IP address line
		startURL := "IP address " + ip + " :"
		urlBlock := common.GetBlockAfterWithStop(body, startURL, "")

		var result []*events.Event

		// Create an event for each URL in the block
		for _, line := range urlBlock {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			event := events.NewEvent("laliga")
			event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}

			if eventDate != nil {
				event.EventDate = email.ParseDate(*eventDate)
			}

			event.IP = ip
			event.URL = line

			result = append(result, event)
		}

		if len(result) == 0 {
			return nil, common.NewParserError("no URLs found in block")
		}

		return result, nil
	}

	return nil, common.NewParserError("unrecognized subject: " + subjectLower)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
