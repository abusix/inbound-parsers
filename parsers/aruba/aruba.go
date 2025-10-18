package aruba

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
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

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)
	subjectLower = strings.ReplaceAll(subjectLower, "\r\n", "")

	// Create base event
	event := events.NewEvent("aruba")

	// Set event date from headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		event.EventDate = email.ParseDate(dateHeader[0])
	}

	// Check for GDPR/legal request (doxing)
	if strings.Contains(body, "GDPR") ||
		strings.Contains(subjectLower, "legal request") ||
		strings.Contains(subjectLower, "richiesta legale") {
		return p.parseDoxing(serializedEmail, body, event)
	}

	// Check for SPAM + DMARC
	if strings.Contains(body, "SPAM") && strings.Contains(body, "DMARC") {
		return p.parseSpam(subjectLower, event)
	}

	// Check for phishing
	if strings.Contains(strings.ToLower(body), "phishing") {
		return p.parsePhishing(serializedEmail, body, event)
	}

	return nil, fmt.Errorf("no matching parser logic found for aruba email")
}

func (p *Parser) parseDoxing(serializedEmail *email.SerializedEmail, body string, event *events.Event) ([]*events.Event, error) {
	event.EventTypes = []events.EventType{events.NewDoxing()}

	patterns := []string{
		`per quanto riguarda\s+(?P<url>http\S+)`,
		`the link(s)? concerned (is|are) the following:\s+(?P<url>http\S+)`,
		`concerning\s+(?P<url>http\S+)`,
		`seguente url della vostra proprietà:\s+(?P<url>http\S+)`,
		`link in questione (sono )?(i |il |è )?seguent(i|e):\s+(?P<url>http\S+)`,
		`per quanto riguarda( l'URL)?:\s+(?P<url>http\S+)`,
		`URLs of which you are a hosting provider:\s+(?P<url>http\S+)`,
		`informazioni personali sulla sua vita:\s+(?P<url>http\S+)`,
		`quanto riguardahttps:\s+(?P<url>http\S+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile("(?i)" + pattern)
		if match := re.FindStringSubmatch(body); match != nil {
			// Find the named group "url"
			for i, name := range re.SubexpNames() {
				if name == "url" && i < len(match) {
					event.URL = match[i]
					return []*events.Event{event}, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no URL pattern matched in doxing email: %s", serializedEmail.Identifier)
}

func (p *Parser) parseSpam(subjectLower string, event *events.Event) ([]*events.Event, error) {
	event.EventTypes = []events.EventType{events.NewSpam()}
	event.IP = subjectLower
	return []*events.Event{event}, nil
}

func (p *Parser) parsePhishing(serializedEmail *email.SerializedEmail, body string, event *events.Event) ([]*events.Event, error) {
	event.EventTypes = []events.EventType{events.NewPhishing()}

	pattern := `phishing .* precisamente\s+(?P<url>http\S+)`
	re := regexp.MustCompile("(?i)" + pattern)

	if match := re.FindStringSubmatch(body); match != nil {
		// Find the named group "url"
		for i, name := range re.SubexpNames() {
			if name == "url" && i < len(match) {
				event.URL = match[i]
				return []*events.Event{event}, nil
			}
		}
	}

	return nil, fmt.Errorf("no phishing URL pattern matched: %s", serializedEmail.Identifier)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
