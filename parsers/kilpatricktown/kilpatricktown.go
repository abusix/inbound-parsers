package kilpatricktown

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
	// Get email body
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Extract owner from "Injured Party:" block
	ownerBlock := common.GetBlockAfterWithStop(body, "Injured Party:", "")
	if len(ownerBlock) == 0 {
		return nil, common.NewParserError("could not find 'Injured Party:' section")
	}
	owner := ownerBlock[0]

	// Extract owner_url using nested find_string_without_markers
	// find_string_without_markers(find_string_without_markers(body, '[3]', ';'), '(', ')')
	step1 := common.FindStringWithoutMarkers(body, "[3]", ";")
	ownerURL := common.FindStringWithoutMarkers(step1, "(", ")")

	// Get event date from email headers
	var eventDate = email.ParseDate("")
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	// Extract URLs from "following URLs" block
	urlBlock := common.GetBlockAfterWithStop(body, "following URLs", "")

	var result []*events.Event
	for _, url := range urlBlock {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}

		event := events.NewEvent("kilpatricktown")
		event.EventDate = eventDate
		event.URL = url

		// Create Copyright event type with owner and official URL
		copyright := events.NewCopyright("", owner, "")
		copyright.OfficialURL = ownerURL
		event.EventTypes = []events.EventType{copyright}

		result = append(result, event)
	}

	if len(result) == 0 {
		return nil, common.NewParserError("no URLs found in 'following URLs' section")
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
