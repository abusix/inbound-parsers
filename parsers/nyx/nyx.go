package nyx

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

	// Check if subject contains spam/junk keywords
	subjectLower := strings.ToLower(subject)
	if !strings.Contains(subjectLower, "spam") && !strings.Contains(subjectLower, "junk") {
		return nil, common.NewNewTypeError(subjectLower)
	}

	event := events.NewEvent("nyx")
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Set event date from email headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		event.EventDate = email.ParseDate(dateHeader[0])
	}

	// Find and parse the Received block
	receivedBlock := common.FindString(body, "Received: from", "\n")
	receivedBlock = strings.TrimSpace(receivedBlock)

	// Get lines after the received block and append continuation lines
	afterReceived := common.GetContinuousLinesUntilEmptyLine(body, receivedBlock)
	for _, line := range afterReceived {
		if strings.HasPrefix(line, "\t") {
			receivedBlock = receivedBlock + " " + strings.TrimSpace(line)
		} else {
			break
		}
	}

	// Try to extract event date from Received block (after semicolon)
	if strings.Contains(receivedBlock, ";") {
		parts := strings.Split(receivedBlock, ";")
		if len(parts) > 0 {
			dateStr := strings.TrimSpace(parts[len(parts)-1])
			if parsedDate := email.ParseDate(dateStr); parsedDate != nil {
				event.EventDate = parsedDate
			}
		}
	}

	// Extract IP address
	// First try X-Originating-IP header
	if xOrigIP := common.FindStringWithoutMarkers(body, "X-Originating-IP:", ""); xOrigIP != "" {
		if validIP := common.IsIP(xOrigIP); validIP != "" {
			event.IP = validIP
		}
	} else {
		// Fall back to extracting from Received block (between brackets)
		if ipFromReceived := common.FindStringWithoutMarkers(receivedBlock, "[", "]"); ipFromReceived != "" {
			if validIP := common.IsIP(ipFromReceived); validIP != "" {
				event.IP = validIP
			}
		}
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
