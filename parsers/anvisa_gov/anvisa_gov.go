package anvisa_gov

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	trackingPattern = regexp.MustCompile(`(?i)(tracking:|rastreamento:) (?P<id>\S+)\)`)
	fraudURLPattern = regexp.MustCompile(`(?i)scam website hosted at your network:\s*(?P<url>http\S+)`)
	fraudIPPattern  = regexp.MustCompile(`(?i)ip: (?P<ip>\S+)`)
)

func NewParser() *Parser {
	return &Parser{}
}

func isURL(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func parseIllegalAdvertisement(body string, eventTemplate *events.Event) ([]*events.Event, error) {
	eventTemplate.EventTypes = []events.EventType{events.NewIllegalAdvertisement()}

	var results []*events.Event
	tags := []string{"ATTACHMENT:", "ANEXO URL(s):"}

	for _, tag := range tags {
		// Replace tag to ensure it's on its own line
		modifiedBody := strings.ReplaceAll(body, tag, tag+"\n")
		urlBlock := common.GetBlockAfterWithStop(modifiedBody, tag, "")

		for _, line := range urlBlock {
			if isURL(line) {
				// Create a copy of the event for each URL
				eventCopy := *eventTemplate
				eventCopy.URL = strings.TrimSpace(line)
				results = append(results, &eventCopy)
			}
		}
	}

	if len(results) > 0 {
		return results, nil
	}

	return nil, common.NewParserError("no URLs found in illegal advertisement report")
}

func parseFraud(body string, event *events.Event) ([]*events.Event, error) {
	event.EventTypes = []events.EventType{events.NewFraud()}

	// Try to find URL
	if match := fraudURLPattern.FindStringSubmatch(body); len(match) > 0 {
		for i, name := range fraudURLPattern.SubexpNames() {
			if name == "url" && i < len(match) {
				event.URL = match[i]
				break
			}
		}
	}

	// Try to find IP
	if match := fraudIPPattern.FindStringSubmatch(body); len(match) > 0 {
		for i, name := range fraudIPPattern.SubexpNames() {
			if name == "ip" && i < len(match) {
				event.IP = match[i]
				break
			}
		}
	}

	return []*events.Event{event}, nil
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

	event := events.NewEvent("anvisa_gov")

	// Get date from headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		event.EventDate = email.ParseDate(dateHeader[0])
	}

	// Extract tracking ID if present
	if match := trackingPattern.FindStringSubmatch(subject); len(match) > 0 {
		for i, name := range trackingPattern.SubexpNames() {
			if name == "id" && i < len(match) {
				event.AddEventDetail(&events.ExternalID{ID: match[i]})
				break
			}
		}
	}

	bodyLower := strings.ToLower(body)

	// Check for illegal advertisement
	illegalAdvertisementKeywords := []string{
		"sanitary legislations in force",
		"health legislations in force",
		"legislações sanitárias vigentes",
	}

	for _, keyword := range illegalAdvertisementKeywords {
		if strings.Contains(bodyLower, keyword) {
			return parseIllegalAdvertisement(body, event)
		}
	}

	// Check for fraud
	if strings.Contains(bodyLower, "we detected a scam website hosted at your network") {
		return parseFraud(body, event)
	}

	return nil, common.NewParserError("unknown email type")
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
