package communicationvalley

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
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	// Clean subject: remove \r and \n
	subject = strings.ReplaceAll(subject, "\r", "")
	subject = strings.ReplaceAll(subject, "\n", "")

	event := events.NewEvent("communicationvalley")

	// Set event_date from headers['date'][0]
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Extract external ID from subject: [CS{id}]
	if externalID := common.FindStringWithoutMarkers(subject, "[CS", "]"); externalID != "" {
		event.AddEventDetail(&events.ExternalID{
			ID: "CS" + externalID,
		})
	}

	// Parse based on subject content
	if strings.Contains(subject, "intermediazione irregolare") {
		return p.parseGhostedBrokerage(event, body)
	}

	if strings.Contains(subject, "fraudulent") {
		return p.parseFraudulentURL(event, body)
	}

	// Unknown type
	return nil, common.NewNewTypeError(subject)
}

func (p *Parser) parseGhostedBrokerage(event *events.Event, body string) ([]*events.Event, error) {
	// Extract IP: 'con IP {ip} '
	event.IP = common.FindStringWithoutMarkers(body, "con IP ", " ")

	// Extract URL: first non-empty line after 'ghost broking'
	event.URL = common.GetNonEmptyLineAfter(body, "ghost broking")

	// Extract official URL if present
	officialURL := ""
	if strings.Contains(body, "legitimate websites URL") {
		rawURL := common.GetNonEmptyLineAfter(body, "legitimate websites URL")
		if processedURL, err := common.ProcessURL(rawURL); err == nil {
			officialURL = processedURL
		}
	}

	// Set event type
	event.EventTypes = []events.EventType{events.NewPhishingWithOfficialURL(officialURL)}

	return []*events.Event{event}, nil
}

func (p *Parser) parseFraudulentURL(event *events.Event, body string) ([]*events.Event, error) {
	// Extract IP: 'IP address:{ip}'
	event.IP = common.FindStringWithoutMarkers(body, "IP address:", "")

	// Extract URL: first line from block after 'the following URL'
	urlBlock := common.GetBlockAfterWithStop(body, "the following URL", "")
	if len(urlBlock) > 0 {
		event.URL = urlBlock[0]
	}

	// Extract official URL if present
	officialURL := ""
	if strings.Contains(body, "legitimate websites URL") {
		rawURL := common.GetNonEmptyLineAfter(body, "legitimate websites URL")
		if processedURL, err := common.ProcessURL(rawURL); err == nil {
			officialURL = processedURL
		}
	}

	// Set event type
	event.EventTypes = []events.EventType{events.NewPhishingWithOfficialURL(officialURL)}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
