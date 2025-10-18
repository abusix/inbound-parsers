package marqvision

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

	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)

	// Create event template
	eventTemplate := events.NewEvent("marqvision")

	// Get date from headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventTemplate.EventDate = email.ParseDate(dateHeader[0])
	}

	// Determine event type based on body content
	if strings.Contains(bodyLower, "trademark") {
		eventTemplate.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}
	} else if strings.Contains(bodyLower, "copyright") {
		eventTemplate.EventTypes = []events.EventType{events.NewCopyright("", "", "")}
	} else {
		return nil, common.NewParserError("unknown event type in body")
	}

	// Extract URL block based on subject type
	var eventBlock []string

	if strings.Contains(subjectLower, "trademark infringement") {
		// Replace order: with order:\n to ensure proper line splitting
		bodyModified := strings.ReplaceAll(body, "order:", "order:\n")
		eventBlock = common.GetBlockAfterWithStop(bodyModified, "Infringing content in no particular order:", "")
	} else if strings.Contains(subjectLower, "infringing content report") {
		// Extract text between markers and split into lines
		extracted := common.FindStringWithoutMarkers(body, "activities.", "The IP Owner")
		eventBlock = strings.Split(strings.TrimSpace(extracted), "\n")
	} else if strings.Contains(subjectLower, "website takedown request") {
		// Get the non-empty line after the marker and split it
		urlLine := common.GetNonEmptyLineAfter(body, "[Infringing URL]")
		eventBlock = strings.Split(urlLine, "\n")
	} else {
		return nil, common.NewParserError("unknown subject type: " + subject)
	}

	// Generate events from URL block
	var results []*events.Event

	for _, urlLine := range eventBlock {
		url := strings.TrimSpace(urlLine)
		if url == "" {
			continue
		}

		// Create a copy of the template event
		event := events.NewEvent("marqvision")
		event.EventDate = eventTemplate.EventDate
		event.EventTypes = eventTemplate.EventTypes
		event.URL = url

		results = append(results, event)
	}

	if len(results) == 0 {
		return nil, common.NewParserError("no URLs found in event block")
	}

	return results, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
