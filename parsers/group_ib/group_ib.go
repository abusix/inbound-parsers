package group_ib

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
	// Get body and subject - both required (throws=True in Python)
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Check if subject contains copyright-related keywords
	subjectLower := strings.ToLower(subject)
	if !strings.Contains(subjectLower, "copyright") && !strings.Contains(subjectLower, "авторского права") {
		return nil, common.NewParserError("subject does not contain copyright keywords")
	}

	// Create event template
	eventTemplate := events.NewEvent("group_ib")
	eventTemplate.EventTypes = []events.EventType{events.NewCopyright("", "", "")}

	// Parse event date from headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventTemplate.EventDate = email.ParseDate(dateHeader[0])
	}

	// Find URL block - try first set of markers
	urlBlock := common.FindStringWithoutMarkers(body, "URLs with violations:", "My contact information is as follows:")

	// If not found, try alternate markers
	if urlBlock == "" {
		urlBlock = common.FindStringWithoutMarkers(body, "URL for your reference:", "In case you are a hosting provider")
	}

	// Parse URLs from the block
	var result []*events.Event
	lines := strings.Split(urlBlock, "\n")
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "http") {
			// Create a copy of the event template for each URL
			event := *eventTemplate
			event.URL = trimmedLine
			result = append(result, &event)
		}
	}

	if len(result) == 0 {
		return nil, common.NewParserError("no URLs found in email body")
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
