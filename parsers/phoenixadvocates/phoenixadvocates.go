package phoenixadvocates

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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, _ := common.GetSubject(serializedEmail, false)

	if strings.Contains(strings.ToLower(subject), "dmca") {
		return p.parseDMCA(body, serializedEmail)
	}

	return nil, common.NewParserError("Could not determine report type")
}

func (p *Parser) parseDMCA(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	var linksBlock []string

	// Find the links block after 'Links:' or 'image:'
	for _, el := range []string{"Links:", "image:"} {
		if strings.Contains(body, el) {
			// Replace the marker to ensure it's on its own line
			modifiedBody := strings.ReplaceAll(body, el, el+"\n")
			linksBlock = common.GetBlockAfterWithStop(modifiedBody, el, "")
			break
		}
	}

	if len(linksBlock) == 0 {
		return nil, common.NewParserError("Could not find links block")
	}

	var eventList []*events.Event

	for _, line := range linksBlock {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Add protocol if missing
		if !strings.Contains(line, "http") && !strings.Contains(line, "hxxp") {
			line = "http://" + line
		}

		event := events.NewEvent("phoenixadvocates")
		event.URL = line
		event.EventTypes = []events.EventType{events.NewCopyright(line, "", "")}

		// Get event date from headers
		if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
			event.EventDate = email.ParseDate(dateHeader[0])
		}

		eventList = append(eventList, event)
	}

	if len(eventList) == 0 {
		return nil, common.NewParserError("No events generated from links block")
	}

	return eventList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
