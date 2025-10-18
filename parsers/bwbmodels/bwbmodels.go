package bwbmodels

import (
	"fmt"
	"strings"

	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// New creates a new parser instance (wrapper for Bento integration)
func New(se email.SerializedEmail, fa, fn, ct string) *Parser {
	// Ignore the parameters - they're not needed for this parser
	_ = se
	_ = fa
	_ = fn
	_ = ct
	return NewParser()
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

	eventTemplate := events.NewEvent("bwbmodels")

	// Set EventDate from email date header
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventTemplate.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	subjectLower := strings.ToLower(subject)

	// Determine event type based on subject
	if strings.Contains(subjectLower, "dmca") {
		return parseCopyright(body, eventTemplate)
	} else if strings.Contains(subjectLower, "doxxing") {
		return parseDoxing(body, eventTemplate)
	} else if strings.Contains(subjectLower, "content removal request") ||
		strings.Contains(subjectLower, "richiesta di rimozione dei contenuti") {
		return parseMaliciousActivity(body, eventTemplate)
	}

	return nil, fmt.Errorf("unknown subject type: %s", subject)
}

func parseCopyright(body string, eventTemplate *events.Event) ([]*events.Event, error) {
	// Normalize the body text
	body = strings.ReplaceAll(body, "URLs", "URL")
	body = strings.ReplaceAll(body, "URL :", "URL:")

	// Find original content URL
	originalContent := common.GetNonEmptyLineAfter(body, "The unauthorised content was taken from a live show on this profile:")
	if originalContent == "" {
		originalContent = common.GetNonEmptyLineAfter(body, "The unauthorised content was taken from this now deleted profile:")
	}

	// Find copyright owner
	copyrightOwner := common.FindStringWithoutMarkers(body, "copyright holder:", ",")
	if copyrightOwner == "" {
		copyrightOwner = common.FindStringWithoutMarkers(body, "on behalf of the model:", ",")
	}

	// Create copyright event type
	copyrightType := &events.Copyright{
		BaseEventType: events.BaseEventType{
			Name: "copyright",
			Type: "copyright",
		},
		CopyrightOwner: strings.TrimSpace(copyrightOwner),
		OfficialURL:    originalContent,
	}

	// Extract URL block
	urlBlock := common.FindStringWithoutMarkers(body, "The specific URL:", "The unauthorised content")

	var result []*events.Event

	// Parse each URL from the block
	lines := strings.Split(urlBlock, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "http") {
			// Create a deep copy of the event
			event := events.NewEvent(eventTemplate.Parser)
			event.EventDate = eventTemplate.EventDate
			event.URL = line
			event.EventTypes = []events.EventType{copyrightType}
			result = append(result, event)
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no URLs found in copyright report")
	}

	return result, nil
}

func parseDoxing(body string, eventTemplate *events.Event) ([]*events.Event, error) {
	doxingType := events.NewDoxing()

	url := common.GetNonEmptyLineAfter(body, "The URL where the information appears:")
	if url == "" {
		return nil, fmt.Errorf("no URL found in doxing report")
	}

	event := events.NewEvent(eventTemplate.Parser)
	event.EventDate = eventTemplate.EventDate
	event.URL = url
	event.EventTypes = []events.EventType{doxingType}

	return []*events.Event{event}, nil
}

func parseMaliciousActivity(body string, eventTemplate *events.Event) ([]*events.Event, error) {
	maliciousType := events.NewMaliciousActivity()

	url := common.GetNonEmptyLineAfter(body, "The specific URL:")
	if url == "" {
		return nil, fmt.Errorf("no URL found in malicious activity report")
	}

	event := events.NewEvent(eventTemplate.Parser)
	event.EventDate = eventTemplate.EventDate
	event.URL = url
	event.EventTypes = []events.EventType{maliciousType}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
