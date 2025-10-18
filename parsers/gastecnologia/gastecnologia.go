// Package gastecnologia implements the gastecnologia parser
// This is a 100% exact Go translation of Python's gastecnologia.py
package gastecnologia

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/base"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the gastecnologia parser
type Parser struct {
	base.BaseParser
}

// New creates a new gastecnologia parser instance
func New() *Parser {
	return &Parser{
		BaseParser: base.NewBaseParser("gastecnologia"),
	}
}

// Parse parses emails from @gastecnologia
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Check if subject contains "phishing"
	if !strings.Contains(strings.ToLower(subject), "phishing") {
		return nil, common.NewNewTypeError(subject)
	}

	// Extract URL (line after "hosted at:")
	url := common.GetNonEmptyLineAfter(body, "hosted at:")
	if url == "" {
		return nil, common.NewParserError("no URL found after 'hosted at:'")
	}

	// Extract IP (line after the URL)
	ip := common.GetNonEmptyLineAfter(body, url)
	if ip == "" {
		return nil, common.NewParserError("no IP found after URL")
	}

	// Clean URL: remove obfuscations and strip asterisks
	url = common.CleanURL(url)
	url = strings.Trim(url, "*")

	// Clean IP: replace [.] with .
	ip = strings.ReplaceAll(ip, "[.]", ".")
	ip = common.ExtractOneIP(ip)
	if ip == "" {
		return nil, common.NewParserError("could not extract valid IP")
	}

	// Extract external ID from subject (between # and space)
	externalID := common.FindStringWithoutMarkers(subject, "#", " ")

	// Create event
	event := events.NewEvent("gastecnologia")
	event.EventTypes = []events.EventType{events.NewPhishing()}

	// Set event date from email headers
	if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
		event.EventDate = email.ParseDate(dates[0])
	}

	event.IP = ip
	event.URL = url

	// Add external ID if found
	if externalID != "" {
		event.AddEventDetail(&events.ExternalID{ID: externalID})
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
