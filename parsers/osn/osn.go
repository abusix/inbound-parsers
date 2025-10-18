// Package osn implements the OSN parser for copyright and trademark reports
package osn

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

var urlPattern = regexp.MustCompile(`^https?://\w+`)

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, common.NewParserError("failed to get email body: " + err.Error())
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, common.NewParserError("failed to get email subject: " + err.Error())
	}

	// Split body at <html> tag, take text before it
	if idx := strings.Index(body, "<html>"); idx != -1 {
		body = body[:idx]
	}

	subjectLower := strings.ToLower(subject)

	if strings.Contains(subjectLower, "copyright") {
		return parseCopyright(body, serializedEmail)
	} else if strings.Contains(subjectLower, "trademark") {
		return parseTrademark(body, serializedEmail, subject)
	}

	return nil, common.NewParserError("could not determine report type from subject")
}

func parseCopyright(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Parse key-value pairs from body
	kvPairs := common.OneLineColonKeyValueGenerator(body)

	// Get Works Name values
	works := kvPairs["Works Name"]

	// Get date from headers
	var eventDate *time.Time
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Get infringing URLs
	infringingURLs := getInfringingURLs(body)
	if len(infringingURLs) == 0 {
		return nil, common.NewParserError("no infringing URLs found")
	}

	var eventsList []*events.Event
	for _, url := range infringingURLs {
		event := events.NewEvent("osn")
		event.EventDate = eventDate
		event.URL = url

		// Create copyright event type
		copyrightWork := strings.Join(works, ", ")
		event.EventTypes = []events.EventType{
			events.NewCopyright(copyrightWork, "OSN", ""),
		}

		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

func parseTrademark(body string, serializedEmail *email.SerializedEmail, subject string) ([]*events.Event, error) {
	// Get date from headers
	var eventDate *time.Time
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Get infringing URLs
	infringingURLs := getInfringingURLs(body)
	if len(infringingURLs) == 0 {
		return nil, common.NewParserError("no infringing URLs found")
	}

	var eventsList []*events.Event
	for _, url := range infringingURLs {
		event := events.NewEvent("osn")
		event.EventDate = eventDate
		event.URL = url

		// Try to parse IP from subject (Python tries this)
		if ip := common.IsIP(subject); ip != "" {
			event.IP = ip
		}

		// Create trademark event type
		event.EventTypes = []events.EventType{
			events.NewTrademark("", nil, "OSN", ""),
		}

		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

func getInfringingURLs(body string) []string {
	var urls []string
	seenURLs := make(map[string]bool)

	lines := strings.Split(body, "\n")
	for _, line := range lines {
		matches := urlPattern.FindAllString(line, -1)
		for _, match := range matches {
			if !seenURLs[match] {
				urls = append(urls, match)
				seenURLs[match] = true
			}
		}
	}

	return urls
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
