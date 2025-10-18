package bradesco

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
	// Get body with throws=True to match Python behavior
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Extract URL - find text after "\nhttp" marker
	marker := "\nhttp"
	startIndex := strings.Index(body, marker)
	if startIndex == -1 {
		return nil, common.NewParserError("URL marker not found in email body")
	}
	startIndex += 1 // Move past the newline
	endIndex := strings.Index(body[startIndex:], "\n")
	if endIndex == -1 {
		endIndex = len(body[startIndex:])
	} else {
		endIndex += startIndex
	}
	url := strings.TrimSpace(body[startIndex:endIndex])

	// Extract IP - find text after "\nIP" marker
	marker = "\nIP"
	startIndex = strings.Index(body, marker)
	if startIndex == -1 {
		return nil, common.NewParserError("IP marker not found in email body")
	}
	startIndex += 1 // Move past the newline
	endIndex = strings.Index(body[startIndex:], "\n")
	if endIndex == -1 {
		endIndex = len(body[startIndex:])
	} else {
		endIndex += startIndex
	}
	ipLine := strings.TrimSpace(body[startIndex:endIndex])
	// Get the last word (split by space and take last element)
	ipParts := strings.Split(ipLine, " ")
	ip := ipParts[len(ipParts)-1]

	// Create event
	event := events.NewEvent("bradesco")
	event.IP = ip
	event.URL = url

	// Create phishing event type
	phishing := events.NewPhishing()
	event.EventTypes = []events.EventType{phishing}

	// Set event_date from headers['date'][0]
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
