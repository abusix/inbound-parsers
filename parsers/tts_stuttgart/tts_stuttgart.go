package tts_stuttgart

import (
	"net/mail"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// parseEventDate extracts the date from the Received header embedded in the body
func parseEventDate(body string) string {
	// Find the "received:" marker in the body
	recvIdx := strings.Index(strings.ToLower(body), "received:")
	if recvIdx == -1 {
		return ""
	}

	// Parse the remaining text as an email message to extract the Received header
	bodyPart := body[recvIdx:]
	msg, err := mail.ReadMessage(strings.NewReader(bodyPart))
	if err != nil {
		return ""
	}

	receivedHeader := msg.Header.Get("Received")
	if receivedHeader == "" {
		return ""
	}

	// Received headers typically have format: "from ... by ... ; <date>"
	// Split by semicolon and take the last part
	parts := strings.Split(receivedHeader, ";")
	if len(parts) < 2 {
		return ""
	}

	dateStr := strings.TrimSpace(parts[len(parts)-1])
	return dateStr
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

	bodyLower := strings.ToLower(body)

	// Extract external ID (processing ID) from body
	externalID := common.FindStringWithoutMarkers(bodyLower, "processing id: ", "")

	// Create the event
	event := events.NewEvent("tts_stuttgart")

	// The IP address is in the subject line
	event.IP = subject

	// Try to parse event date from the Received header in the body
	eventDateStr := parseEventDate(body)
	if eventDateStr != "" {
		// Parse the date string
		event.EventDate = email.ParseDate(eventDateStr)
	}

	// Fallback to email header date if parsing failed
	if event.EventDate == nil {
		if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
			event.EventDate = email.ParseDate(dateHeader[0])
		}
	}

	// Set event type to Spam
	event.EventTypes = []events.EventType{events.NewSpam()}

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
