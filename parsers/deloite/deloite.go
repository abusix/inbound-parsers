package deloite

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
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Strip HTML tags - replace <br> with newlines and remove other tags
	text := strings.ReplaceAll(body, "<br>", "\n")
	text = strings.ReplaceAll(text, "<br/>", "\n")
	text = strings.ReplaceAll(text, "<br />", "\n")
	// Remove all remaining HTML tags
	re := regexp.MustCompile(`<[^>]+>`)
	text = re.ReplaceAllString(text, "")

	subjectLower := strings.ToLower(subject)

	// Route based on subject
	if strings.Contains(subjectLower, "phishing") {
		return parsePhishing(serializedEmail, text)
	} else if strings.Contains(subjectLower, "malware") {
		return parseMalware(serializedEmail, text)
	} else if strings.Contains(subjectLower, "trademark") || strings.Contains(subjectLower, "url abuse") {
		return parseTrademark(serializedEmail, text)
	}

	return nil, common.NewParserError("Unknown email type: " + subject)
}

func parsePhishing(serializedEmail *email.SerializedEmail, text string) ([]*events.Event, error) {
	event := events.NewEvent("deloite")

	// Extract URL
	event.URL = common.GetNonEmptyLineAfter(text, "Affected URLs")

	// Extract IP
	ipStr := common.FindStringWithoutMarkers(text, "IP: ", "-")
	event.IP = strings.TrimSpace(ipStr)

	// Set event date from email date header
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Set event type
	phishing := events.NewPhishing()
	event.EventTypes = []events.EventType{phishing}

	return []*events.Event{event}, nil
}

func parseTrademark(serializedEmail *email.SerializedEmail, text string) ([]*events.Event, error) {
	event := events.NewEvent("deloite")

	// Try to extract URL - first attempt GetNonEmptyLineAfter, fallback to FindStringWithoutMarkers
	url := common.GetNonEmptyLineAfter(text, "Affected URL")
	if url == "" {
		url = common.FindStringWithoutMarkers(text, "Affected URL:", "")
	}
	event.URL = url

	// Try to extract IP - first attempt GetNonEmptyLineAfter, fallback to FindStringWithoutMarkers
	ipStr := common.GetNonEmptyLineAfter(text, "IP:")
	if ipStr == "" {
		ipStr = common.FindStringWithoutMarkers(text, "IP:", "")
	}
	event.IP = strings.TrimSpace(ipStr)

	// Extract trademark details
	ownerName := common.FindStringWithoutMarkers(text, "Name:", "")
	country := common.FindStringWithoutMarkers(text, "Country:", "")
	registrationNumber := common.FindStringWithoutMarkers(text, "Registration Number:", "")
	officialURL := common.FindStringWithoutMarkers(text, "Website:", "")

	// Set event date from email date header
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Build registration numbers array
	var registrationNumbers []string
	if registrationNumber != "" {
		registrationNumbers = []string{registrationNumber}
	}

	// Create trademark event type
	trademark := events.NewTrademark(country, registrationNumbers, ownerName, "")
	trademark.OfficialURL = officialURL
	event.EventTypes = []events.EventType{trademark}

	return []*events.Event{event}, nil
}

func parseMalware(serializedEmail *email.SerializedEmail, text string) ([]*events.Event, error) {
	event := events.NewEvent("deloite")

	// Try to extract URL using FindStringWithoutMarkers first
	url := common.FindStringWithoutMarkers(text, "URL:", "")
	url = strings.TrimSpace(url)
	if url != "" && len(url) > 0 && !isDigit(url[0]) {
		event.URL = url
	} else {
		// Fallback to GetNonEmptyLineAfter
		url = common.GetNonEmptyLineAfter(text, "URL:")
		if url != "" && len(url) > 0 && !isDigit(url[0]) {
			event.URL = url
		}
	}

	// Try to extract IP
	ipStr := common.FindStringWithoutMarkers(text, "IP:", "")
	if ipStr != "" {
		event.IP = ipStr
	} else {
		ipStr = common.FindStringWithoutMarkers(text, "Affected IP/URL:", "")
		event.IP = strings.TrimSpace(ipStr)
	}

	// Set event date from email date header
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Extract malware family
	malwareFamily := common.FindStringWithoutMarkers(text, "Malware family:", "")

	// Create malware event type
	malware := events.NewMalware(malwareFamily)
	event.EventTypes = []events.EventType{malware}

	return []*events.Event{event}, nil
}

// isDigit checks if a byte represents a digit character
func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
