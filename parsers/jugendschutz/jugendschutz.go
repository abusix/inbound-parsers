package jugendschutz

import (
	"strings"

	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	subjectLower := strings.ToLower(subject)

	// Check if this is a CSAM report
	if strings.Contains(subjectLower, "child sexual") || strings.Contains(subjectLower, "csam") {
		return p.parseCSAM(body, serializedEmail)
	}

	// Unknown subject type
	return nil, common.NewNewTypeError(subject)
}

func (p *Parser) parseCSAM(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	event := events.NewEvent("jugendschutz")
	event.EventTypes = []events.EventType{events.NewChildAbuse()}

	// Set event date from email date header
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	bodyLower := strings.ToLower(body)

	// Extract IP if present
	if strings.Contains(bodyLower, "ip:") {
		ip := common.FindStringWithoutMarkers(bodyLower, "ip:", "")
		event.IP = strings.TrimSpace(ip)
	}

	// Extract URL
	url := common.GetNonEmptyLineAfter(bodyLower, "a report on the following url")
	if url != "" {
		event.URL = url
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
