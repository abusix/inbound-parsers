package tvb

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
	// Get email body and subject
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("no email body found")
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, common.NewParserError("no email subject found")
	}

	// Normalize text for parsing
	bodyLower := strings.ToLower(strings.ReplaceAll(body, "\r\n", "\n"))
	subjectLower := strings.ToLower(subject)

	// Check if this is a copyright/DMCA report based on subject
	if !strings.Contains(subjectLower, "copyright") && !strings.Contains(subjectLower, "dmca") {
		return nil, common.NewNewTypeError(subjectLower)
	}

	// Create event
	event := events.NewEvent("tvb")
	event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}

	// Set event date from email date header
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Extract IP address - try two different patterns
	ip := common.FindStringWithoutMarkers(bodyLower, "with the ip", "")
	if ip == "" {
		ip = common.FindStringWithoutMarkers(bodyLower, "ip address:", "")
	}
	event.IP = ip

	// Extract URL - try two different patterns
	url := common.GetNonEmptyLineAfter(bodyLower, "with the ip")
	if url == "" {
		url = common.GetNonEmptyLineAfter(bodyLower, "copyright infringed materials are identified as follows")
	}
	event.URL = url

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
