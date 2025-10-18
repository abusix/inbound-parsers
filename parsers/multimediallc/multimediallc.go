package multimediallc

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
	// Get body
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("no body found")
	}

	// Get date from headers
	var dateStr string
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			dateStr = dateHeaders[0]
		}
	}
	if dateStr == "" {
		return nil, common.NewParserError("no date found")
	}

	// Parse the date
	eventDate := email.ParseDate(dateStr)
	if eventDate == nil {
		return nil, common.NewParserError("could not parse date")
	}

	// Extract official URL
	officialURL := common.FindStringWithoutMarkers(body, "without authorization from ", " ")

	// Parse URLs from the evidence section
	var urls []string
	inEvidenceURLSection := false

	lines := strings.Split(body, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Reported URL") {
			inEvidenceURLSection = true
		} else if strings.Contains(line, "Dear Sir or Madam:") {
			inEvidenceURLSection = false
		}

		if inEvidenceURLSection && line != "" && strings.Contains(line, "http") {
			urls = append(urls, line)
		}
	}

	// Create events for each URL
	var result []*events.Event
	for _, url := range urls {
		event := events.NewEvent("multimediallc")
		event.EventDate = eventDate
		event.URL = url

		// Create Copyright event type with official URL
		copyright := events.NewCopyright("", "", "")
		copyright.OfficialURL = officialURL
		event.EventTypes = []events.EventType{copyright}

		result = append(result, event)
	}

	if len(result) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
