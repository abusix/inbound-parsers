package cavac

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	malwarePattern = regexp.MustCompile(`^(?P<malware>\w+) malware detected`)
)

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	bodyLower := strings.ToLower(body)

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	// Extract malware name from subject
	match := malwarePattern.FindStringSubmatch(subjectLower)
	if match == nil {
		return nil, common.NewParserError("could not match malware pattern in subject: " + subjectLower)
	}

	malwareName := match[1]

	// Create event
	event := events.NewEvent("cavac")
	event.EventTypes = []events.EventType{events.NewMalware(malwareName)}

	// Extract event date
	eventDateStr := common.GetNonEmptyLineAfter(bodyLower, "approximate logtime:")
	if eventDateStr != "" {
		event.EventDate = email.ParseDate(eventDateStr)
	}

	// Extract IP address
	ipAddr := common.FindStringWithoutMarkers(bodyLower, "ip address:", "")
	if ipAddr != "" {
		event.IP = ipAddr
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
