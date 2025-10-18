// Package leakserv implements the leakserv parser
// This is a 100% exact Go translation of Python's leakserv.py
package leakserv

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/base"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the leakserv parser
type Parser struct {
	base.BaseParser
}

// New creates a new leakserv parser instance
func New() *Parser {
	return &Parser{
		BaseParser: base.NewBaseParser("leakserv"),
	}
}

// Parse parses emails from legal@leakserv.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || strings.TrimSpace(body) == "" {
		// Try to get body from parts[0]
		if len(serializedEmail.Parts) > 0 {
			if partBody, ok := serializedEmail.Parts[0].Body.(string); ok {
				body = partBody
			}
		}
		if body == "" {
			return nil, common.NewParserError("no body found")
		}
	}

	event := events.NewEvent("leakserv")

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Parse the body
	lines := strings.Split(body, "\n")
	var copyrightHolder, domain string

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		// Extract domain from "client" line
		if strings.HasPrefix(line, "client") {
			// Split by "client " and then by ","
			if parts := strings.Split(line, "client "); len(parts) > 1 {
				domain = strings.Split(parts[1], ",")[0]
			}
		}

		// Extract copyright holder from "represents" line
		if strings.HasPrefix(line, "represents") {
			// Split by "represents " and then by " (hereinafter"
			if parts := strings.Split(line, "represents "); len(parts) > 1 {
				copyrightHolder = strings.Split(parts[1], " (hereinafter")[0]
			}
		}

		// Extract URL - collect multi-line URLs
		if strings.Contains(line, "://") {
			var urlBuilder strings.Builder
			for j := i; j < len(lines); j++ {
				if strings.TrimSpace(lines[j]) == "" {
					break
				}
				urlBuilder.WriteString(lines[j])
			}
			event.URL = urlBuilder.String()
		}

		// Extract IP address
		if strings.Contains(line, "IP address") {
			// Get the last part after splitting by space
			parts := strings.Fields(line)
			if len(parts) > 0 {
				event.IP = parts[len(parts)-1]
			}
		}
	}

	// If no URL was found, use the domain
	if event.URL == "" {
		event.URL = domain
	}

	// Create Copyright event type
	copyright := events.NewCopyright("", copyrightHolder, "")
	event.EventTypes = []events.EventType{copyright}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
