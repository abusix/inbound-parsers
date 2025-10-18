package fmtsoperation

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
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Process body: replace <br> tags, normalize ' : ' to ': ', and lowercase
	body = strings.ReplaceAll(body, "<br>", "")
	body = strings.ReplaceAll(body, " : ", ": ")
	body = strings.ToLower(body)

	// Check if 'copyright' is in the body
	if !strings.Contains(body, "copyright") {
		return nil, common.NewNewTypeError(subject)
	}

	// Create event
	event := events.NewEvent("fmtsoperation")

	// Set event date from headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate := email.ParseDate(dateHeaders[0])
		event.EventDate = eventDate
	}

	// Set event types
	event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}

	// Set IP from subject (the entire subject is the IP)
	event.IP = subject

	// Extract URL from body using 'illegal broadcast url:' marker
	url := common.FindStringWithoutMarkers(body, "illegal broadcast url:", "")
	if url != "" {
		event.URL = url
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
