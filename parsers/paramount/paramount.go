// Package paramount implements the paramount parser
package paramount

import (
	"regexp"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the paramount parser
type Parser struct{}

var (
	urlPattern = regexp.MustCompile(`(?P<url>https\S+)`)
)

// NewParser creates a new paramount parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from paramount
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Get date from headers
	dateFallback := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateFallback = dateHeaders[0]
	}

	var result []*events.Event

	// Find all URLs in the body
	matches := urlPattern.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 {
			event := events.NewEvent("paramount")
			event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}
			event.EventDate = email.ParseDate(dateFallback)
			event.URL = match[1]
			result = append(result, event)
		}
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
