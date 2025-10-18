package svbuero

import (
	"fmt"
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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)

	if strings.Contains(subjectLower, "hacking from your ip range") {
		return parseWebHack(body)
	}

	return nil, fmt.Errorf("unknown subject type: %s", subject)
}

func parseWebHack(body string) ([]*events.Event, error) {
	event := events.NewEvent("svbuero")
	event.EventTypes = []events.EventType{events.NewWebHack()}

	// Split body by 'Note: All timestamps are UTC'
	parts := strings.Split(body, "Note: All timestamps are UTC")
	if len(parts) == 0 {
		return nil, fmt.Errorf("could not find info block")
	}

	infoBlock := parts[0]

	// Extract URL: try to break into our websystem (URL)
	url := common.FindStringWithoutMarkers(infoBlock, "try to break into our websystem (", ")")
	if url != "" {
		event.URL = url
	}

	// Extract IP from info block
	event.IP = common.ExtractOneIP(infoBlock)

	// Extract event date: date and time of <date>
	eventDateStr := common.FindStringWithoutMarkers(infoBlock, "date and time of ", "\n")
	if eventDateStr != "" {
		event.EventDate = email.ParseDate(eventDateStr)
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
