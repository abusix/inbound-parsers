package brandshield

import (
	"regexp"
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
	// Get body with throws=true to match Python behavior
	bodyRaw, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Get subject with throws=true
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Clean up HTML tags from body
	body := bodyRaw
	body = strings.ReplaceAll(body, "<p>", "")
	body = strings.ReplaceAll(body, "</p>", "")
	body = strings.ReplaceAll(body, "<strong>", "")
	body = strings.ReplaceAll(body, "</strong>", "")
	body = strings.ReplaceAll(body, "<u>", "")
	body = strings.ReplaceAll(body, "</u>", "")
	body = strings.ReplaceAll(body, "Brandshield", "BrandShield")

	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)

	// Create event template
	eventTemplate := events.NewEvent("brandshield")

	// Set event date from headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventTemplate.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Determine event type based on body and subject content
	if strings.Contains(bodyLower, "phishing") || strings.Contains(subjectLower, "phishing") {
		eventTemplate.EventTypes = []events.EventType{events.NewPhishing()}
	} else if strings.Contains(bodyLower, "trademark") {
		eventTemplate.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}
	} else if strings.Contains(bodyLower, "copyright") {
		eventTemplate.EventTypes = []events.EventType{events.NewCopyright("", "", "")}
	} else if strings.Contains(bodyLower, "clear violation of user privacy and security") {
		eventTemplate.EventTypes = []events.EventType{events.NewMaliciousActivity()}
	} else if strings.Contains(bodyLower, "pharmaceutical sales") {
		eventTemplate.EventTypes = []events.EventType{events.NewIllegalAdvertisement()}
	} else {
		return nil, common.NewNewTypeError(subject)
	}

	var result []*events.Event

	// Try to extract URL from subject using regex pattern
	pattern := regexp.MustCompile(`(?i)(violations|notification|rights|infringement|domain|pharmaceutical sales)\s*(?:–|-)\s*(\S+\.\S+)`)
	if match := pattern.FindStringSubmatch(subject); match != nil && len(match) > 2 {
		event := *eventTemplate
		event.URL = match[2]
		result = append(result, &event)
		return result, nil
	}

	// Extract URL part from body using markers
	startMarker := ""
	markers := []string{
		"For example:",
		"following website",
		"following links",
		"following list of URLs",
		"the following listings",
		"the following URL's –",
		"goodwill and reputation:",
		" the items listed below",
		" following URL",
		"without our permission here:",
	}

	for _, marker := range markers {
		if strings.Contains(body, marker) {
			startMarker = marker
			break
		}
	}

	var urlPart string
	if startMarker == "" {
		urlPart = common.FindStringWithoutMarkers(body, "on the listing", "Such unauthorized")
	} else {
		urlPart = common.FindStringWithoutMarkers(body, startMarker, "BrandShield")
	}

	// Extract URLs from urlPart
	lines := strings.Split(urlPart, "\n")
	for _, line := range lines {
		if strings.Contains(line, "http") {
			event := *eventTemplate
			event.URL = strings.TrimSpace(line)
			result = append(result, &event)
		}
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
