package ish

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
	// Get body and subject
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("no email body found")
	}

	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	// Check if this is a known type
	if !strings.Contains(subjectLower, "phishing") && !strings.Contains(subjectLower, "takedown request") {
		return nil, common.NewNewTypeError(subjectLower)
	}

	// Create base event
	event := events.NewEvent("ish")

	// Set event date from headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		event.EventDate = email.ParseDate(dateHeader[0])
	}

	// Initially set as Bot event type
	event.EventTypes = []events.EventType{events.NewBot("")}

	// Extract URL from body
	urlPattern := regexp.MustCompile(`(?i)(suspicious activity can be found at:)\s*(?P<url>http.*)`)
	if urlMatch := urlPattern.FindStringSubmatch(body); urlMatch != nil {
		// Extract the URL from the named group
		for i, name := range urlPattern.SubexpNames() {
			if name == "url" && i < len(urlMatch) {
				event.URL = urlMatch[i]
				break
			}
		}
	}

	// Extract official URL
	var officialURL string
	if officialURLRaw := common.GetNonEmptyLineAfter(body, "legitimate website is:"); officialURLRaw != "" {
		officialURL = strings.ReplaceAll(officialURLRaw, " -", "")
	}

	// If we have a URL, upgrade to Phishing event type
	if event.URL != "" {
		event.EventTypes = []events.EventType{events.NewPhishingWithOfficialURL(officialURL)}
		return []*events.Event{event}, nil
	}

	return nil, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
