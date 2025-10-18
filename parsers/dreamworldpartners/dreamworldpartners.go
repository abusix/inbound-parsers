package dreamworldpartners

import (
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get body and subject
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("no email body found")
	}

	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	// Get event date from email headers
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	// Handle Trademark Violation Notice
	if strings.Contains(subjectLower, "trademark violation notice") {
		event := events.NewEvent("dreamworldpartners")
		event.EventDate = eventDate
		event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}

		// Extract URL
		url := common.GetNonEmptyLineAfter(body, "Material That is Infringing Above Trademark:")
		if url == "" {
			url = common.GetNonEmptyLineAfter(body, "The infringing material is located at the following URL(s):")
		}
		event.URL = url

		return []*events.Event{event}, nil
	}

	// Handle Copyright Infringement or DMCA Takedown Notice
	if strings.Contains(subjectLower, "copyright infringement") || strings.Contains(subjectLower, "dmca takedown notice") {
		event := events.NewEvent("dreamworldpartners")
		event.EventDate = eventDate

		// Extract official URL
		officialURL := common.GetNonEmptyLineAfter(body, "The original material is located at the following URL(s):")

		// Create Copyright event type with official URL
		copyrightEvent := events.NewCopyright("", "", "")
		copyrightEvent.OfficialURL = officialURL
		event.EventTypes = []events.EventType{copyrightEvent}

		// Extract infringing URL
		event.URL = common.GetNonEmptyLineAfter(body, "The infringing material is located at the following URL(s):")

		return []*events.Event{event}, nil
	}

	// Handle Open Redirect Vulnerability
	if strings.Contains(subjectLower, "open redirect vulnerability") {
		event := events.NewEvent("dreamworldpartners")
		event.EventDate = eventDate
		event.EventTypes = []events.EventType{events.NewOpen("")}

		// Extract IP
		event.IP = common.FindStringWithoutMarkers(body, "IP", "")

		// Extract URL
		event.URL = common.FindStringWithoutMarkers(body, "Open redirect URL:", "If possible")

		return []*events.Event{event}, nil
	}

	// Unknown type - raise NewTypeError
	return nil, common.NewNewTypeError(subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
