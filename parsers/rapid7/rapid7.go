package rapid7

import (
	"fmt"
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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	event := events.NewEvent("rapid7")

	// Determine event type based on subject content
	subjectLower := strings.ToLower(subject)
	if strings.Contains(subjectLower, "fraudulent") {
		event.EventTypes = []events.EventType{events.NewFraud()}
	} else if strings.Contains(subjectLower, "的钓鱼网站") {
		event.EventTypes = []events.EventType{events.NewPhishing()}
	} else {
		return nil, fmt.Errorf("unknown event type in subject: %s", subject)
	}

	// Set event date from email headers
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventDate := email.ParseDate(dateHeaders[0])
			event.EventDate = eventDate
		}
	}

	// Extract URL from subject
	// Remove all whitespace from subject
	subjectNoSpace := regexp.MustCompile(`\s`).ReplaceAllString(subject, "")

	// Find URL pattern: (hxxp|http).*
	urlPattern := regexp.MustCompile(`(?P<url>(hxxp|http).*)`)
	urlMatch := urlPattern.FindStringSubmatch(subjectNoSpace)
	if urlMatch == nil {
		return nil, fmt.Errorf("no URL found in subject")
	}

	// Extract the URL and clean it
	url := urlMatch[0]
	url = strings.ReplaceAll(url, "(.)", ".")
	event.URL = url

	// Extract IP from body
	ip := common.FindStringWithoutMarkers(body, "IP number", "This website")
	if ip != "" {
		event.IP = ip
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
