// Package perso implements the perso.be parser
package perso

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the perso parser
type Parser struct{}

// Parse parses emails from pgeens@perso.be
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Get default event date from headers
	var eventDateStr string
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDateStr = dateHeaders[0]
	}

	subjectLower := strings.ToLower(subject)

	if strings.Contains(subjectLower, "fw:") {
		return parseForwarded(body, eventDateStr)
	}

	return nil, common.NewNewTypeError(subjectLower)
}

func parseForwarded(body, eventDateStr string) ([]*events.Event, error) {
	event := events.NewEvent("perso")

	// Set default event date
	eventDate := email.ParseDate(eventDateStr)
	event.EventDate = eventDate

	// Set event type
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Find the Received block
	receivedBlock := common.FindString(body, "Received: from", "\n")
	receivedBlock = strings.TrimSpace(receivedBlock)

	// Get continuous lines until empty line and append tab-indented lines
	afterReceived := common.GetContinuousLinesUntilEmptyLine(body, receivedBlock)
	for _, line := range afterReceived {
		if strings.HasPrefix(line, "\t") {
			receivedBlock = receivedBlock + " " + strings.TrimSpace(line)
		} else {
			break
		}
	}

	// Try to extract date from Received block (after semicolon)
	parts := strings.Split(receivedBlock, ";")
	if len(parts) > 1 {
		dateStr := strings.TrimSpace(parts[len(parts)-1])
		if parsedDate := email.ParseDate(dateStr); parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	// Extract IP from Received block
	ip := common.FindStringWithoutMarkers(receivedBlock, "Received: from", "]")
	event.IP = ip

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
