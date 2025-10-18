package websteiner

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/parsers/common"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	fromAddr, _ := common.GetFrom(serializedEmail, false)
	if !strings.Contains(fromAddr, "bernhard@websteiner.com") {
		return nil, nil
	}

	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)

	// Check if subject contains "fwd:"
	if !strings.Contains(subjectLower, "fwd:") {
		// NewTypeError - subject doesn't contain fwd:
		return nil, nil
	}

	event := events.NewEvent("websteiner")
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Extract received block
	receivedBlock := common.FindString(bodyLower, "received:", "])")
	if receivedBlock == "" {
		return nil, nil
	}

	receivedBlock = strings.TrimSpace(receivedBlock)

	// Get continuous lines until empty line
	lines := strings.Split(receivedBlock, "\n")
	if len(lines) > 0 {
		lastLine := lines[len(lines)-1]
		blockAfter := common.GetContinuousLinesUntilEmptyLine(bodyLower, lastLine)

		// Add continuation lines that start with tab or double space
		for _, line := range blockAfter {
			if strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "  ") {
				receivedBlock = receivedBlock + " " + strings.TrimSpace(line)
			} else {
				break
			}
		}
	}

	// Extract event date from received block (last part after semicolon)
	parts := strings.Split(receivedBlock, ";")
	if len(parts) > 0 {
		dateStr := strings.TrimSpace(parts[len(parts)-1])
		if eventDate := email.ParseDate(dateStr); eventDate != nil {
			event.EventDate = eventDate
		}
	}

	// Try to extract IP from x-originating-ip header first
	ipFromHeader := common.FindStringWithoutMarkers(bodyLower, "x-originating-ip:", "\n")
	if ipFromHeader != "" {
		event.IP = ipFromHeader
	} else {
		// Fallback to extracting IP from received block (between brackets)
		ipFromReceived := common.FindStringWithoutMarkers(receivedBlock, "[", "]")
		if ipFromReceived != "" {
			event.IP = ipFromReceived
		}
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
