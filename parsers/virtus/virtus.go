package virtus

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the Virtus parser for login attack reports
type Parser struct{}

// NewParser creates a new Virtus parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from @virtus.* containing unauthorized access attempts
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get email body
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Check if this is a Virtus unauthorized access report
	if !strings.Contains(strings.ToLower(body), "attempting unauthorized access") {
		return nil, common.NewNewTypeError("adapt the parser")
	}

	// Extract date and destination IP using regex: "(date)","(ip)"
	// Pattern: "([\d\- :\.]*)","([\d\.]*)"
	re := regexp.MustCompile(`"([\d\- :\.]*)","([\d\.]*)"`)
	matches := re.FindStringSubmatch(body)

	if len(matches) < 3 {
		return nil, common.NewParserError("format changed adapt the parser")
	}

	date := matches[1]
	dstIP := matches[2]

	// Get source IP from subject
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Create event
	event := events.NewEvent("virtus")
	event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

	// Set source IP from subject
	if validIP := common.IsIP(subject); validIP != "" {
		event.IP = validIP
	} else {
		event.IP = subject
	}

	// Parse and set event date
	if date != "" {
		eventDate := email.ParseDate(date)
		event.EventDate = eventDate
	}

	// Add target IP as event detail
	if dstIP != "" {
		event.AddEventDetail(&events.Target{IP: dstIP})
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
