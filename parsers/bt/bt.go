package bt

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
	// Check if email has parts (Python: if len(serialized_email['parts']))
	if len(serializedEmail.Parts) == 0 {
		return nil, nil
	}

	// Get the first part's body and remove carriage returns
	// Python: body = remove_carriage_return(serialized_email['parts'][0]['body_raw'])
	firstPartBody, err := getPartBody(serializedEmail.Parts[0])
	if err != nil {
		return nil, &common.ParserError{Message: "failed to get first part body"}
	}
	body := common.RemoveCarriageReturn(firstPartBody)

	// Try to find URL between "hxxp" and "\nThis"
	// Python: url = find_string(body, 'hxxp', '\nThis', ignore_case=True).replace('\nThis', '')
	url := common.FindString(strings.ToLower(body), "hxxp", "\nthis")
	url = strings.ReplaceAll(url, "\nthis", "")
	url = strings.ReplaceAll(url, "\nThis", "")
	url = strings.TrimSpace(url)

	// If not a valid URL, try "http" to "\nThe"
	if !common.IsURL(url) {
		// Python: url = find_string(body, 'http', '\nThe').replace('\nThe', '')
		url = common.FindString(body, "http", "\nThe")
		url = strings.ReplaceAll(url, "\nThe", "")
		url = strings.TrimSpace(url)

		if !common.IsURL(url) {
			return nil, &common.ParserError{Message: "url not found"}
		}
	}

	// Create event with Phishing type
	// Python: event = Event('bt')
	// Python: event.event_types = Phishing(phishing_url=url)
	event := events.NewEvent("bt")
	phishing := events.NewPhishing()
	phishing.PhishingTarget = url
	event.EventTypes = []events.EventType{phishing}

	// Set event_date from headers['date'][0]
	// Python: event.event_date = serialized_email['headers']['date'][0]
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Set URL field
	// Python: event.url = url
	event.URL = url

	return []*events.Event{event}, nil
}

// getPartBody extracts the body from an EmailPart
func getPartBody(part email.EmailPart) (string, error) {
	switch body := part.Body.(type) {
	case string:
		return body, nil
	case []byte:
		return string(body), nil
	default:
		return "", &common.ParserError{Message: "unexpected part body type"}
	}
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
