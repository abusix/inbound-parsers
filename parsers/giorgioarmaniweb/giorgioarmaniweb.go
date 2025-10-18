package giorgioarmaniweb

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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)

	// Check if subject contains trademark or notice of infringement
	if strings.Contains(subjectLower, "trademark") || strings.Contains(subjectLower, "notice of infringement") {
		return p.parseTrademark(body, serializedEmail)
	}

	return nil, common.NewNewTypeError(subject)
}

func (p *Parser) parseTrademark(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Create event template
	eventTemplate := events.NewEvent("giorgioarmaniweb")

	// Set event date from headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventTemplate.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Set event type to Trademark
	eventTemplate.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}

	var result []*events.Event
	foundURL := false

	// Look for URL markers
	tags := []string{"Infringing Material at:", "Infringing URLs:"}

	for _, tag := range tags {
		if strings.Contains(body, tag) {
			// Replace tag with tag + newline to ensure proper block extraction
			modifiedBody := strings.ReplaceAll(body, tag, tag+"\n")

			// Extract block after tag
			urlBlock := common.GetBlockAfterWithStop(modifiedBody, tag, "")

			// Extract URLs from block
			for _, line := range urlBlock {
				if strings.Contains(line, "http") {
					event := *eventTemplate
					event.URL = strings.TrimSpace(line)
					result = append(result, &event)
					foundURL = true
				}
			}
			break
		}
	}

	if !foundURL {
		return nil, &common.ParserError{Message: "Couldn't find Trademark URL"}
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
