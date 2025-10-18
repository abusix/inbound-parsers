package innotec

import (
	"regexp"
	"strings"
	"time"

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

	// Get date fallback from headers
	var dateFallback *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateFallback = email.ParseDate(dateHeaders[0])
	}

	subjectLower := strings.ToLower(subject)

	// Check subject for event type
	if strings.Contains(subjectLower, "phishing") || strings.Contains(subjectLower, "trademark") {
		return p.parsePhishingTrademark(body, dateFallback)
	} else if strings.Contains(subjectLower, "malware") {
		return p.parseMalware(body, dateFallback)
	}

	return nil, common.NewParserError("Unknown subject type: " + subject)
}

func (p *Parser) parsePhishingTrademark(body string, dateFallback *time.Time) ([]*events.Event, error) {
	bodyLower := strings.ToLower(body)

	var eventsList []*events.Event

	// Check for various tags
	tags := []string{"following url(s)", "following urls:", "distrust the link:"}
	for _, tag := range tags {
		if strings.Contains(bodyLower, tag) {
			urls := common.GetBlockAfterWithStop(bodyLower, tag, "")
			for _, urlStr := range urls {
				// Remove spaces
				urlStr = strings.ReplaceAll(urlStr, " ", "")

				event := events.NewEvent("innotec")
				event.EventDate = dateFallback
				event.EventTypes = []events.EventType{events.NewPhishing()}
				event.URL = urlStr

				eventsList = append(eventsList, event)
			}
			break
		}
	}

	return eventsList, nil
}

func (p *Parser) parseMalware(body string, dateFallback *time.Time) ([]*events.Event, error) {
	event := events.NewEvent("innotec")

	// Try to find URL
	urlPattern := regexp.MustCompile(`(?i)(from the following URL(?:\(s\))?|affected URL(?:\(s\))? were):\s*([^\n]+)`)
	if match := urlPattern.FindStringSubmatch(body); match != nil && len(match) > 2 {
		event.URL = strings.ReplaceAll(match[2], " ", "")
	}

	// Try to find IP
	ipPattern := regexp.MustCompile(`(?i)(with this IP:|affected IP(?:\(s\))? were:|the following IP:)\s*\[?(\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3})`)
	if match := ipPattern.FindStringSubmatch(body); match != nil && len(match) > 2 {
		ipStr := match[2]
		ipStr = strings.ReplaceAll(ipStr, " ", "")
		ipStr = strings.ReplaceAll(ipStr, "[", "")
		ipStr = strings.ReplaceAll(ipStr, "]", "")
		event.IP = ipStr
	}

	// Only create event if we have IP or URL
	if event.IP != "" || event.URL != "" {
		event.EventDate = dateFallback
		event.EventTypes = []events.EventType{events.NewMalware("")}
		return []*events.Event{event}, nil
	}

	return nil, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
