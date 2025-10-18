package puig

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/parsers/common"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// getURL ensures URL has http:// prefix
func getURL(url string) string {
	if !strings.Contains(url, "http") {
		return "http://" + url
	}
	return url
}

// parseTrademark parses trademark infringement reports
func parseTrademark(body string, eventTemplate *events.Event, dateFallback string) ([]*events.Event, error) {
	var result []*events.Event

	eventTemplate.EventDate = email.ParseDate(dateFallback)
	eventTemplate.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}

	// Try multiple tag variations to find URLs
	tags := []string{
		"url(s):",
		"urls:",
		"website(s):",
		"can be found at:",
	}

	foundURLs := false
	bodyLower := strings.ToLower(body)

	for _, tag := range tags {
		if strings.Contains(bodyLower, tag) {
			// Replace tag to ensure it's on its own line for GetBlockAfter
			bodyWithNewline := strings.Replace(bodyLower, tag, tag+"\n", 1)
			urls := common.GetBlockAfterWithStop(bodyWithNewline, tag, "")

			for _, url := range urls {
				event := events.NewEvent(eventTemplate.Parser)
				event.EventDate = eventTemplate.EventDate
				event.EventTypes = make([]events.EventType, len(eventTemplate.EventTypes))
				copy(event.EventTypes, eventTemplate.EventTypes)
				event.URL = getURL(url)
				result = append(result, event)
				foundURLs = true
			}
			break
		}
	}

	// If no URLs found via tags, try regex patterns
	if !foundURLs {
		event := events.NewEvent(eventTemplate.Parser)
		event.EventDate = eventTemplate.EventDate
		event.EventTypes = make([]events.EventType, len(eventTemplate.EventTypes))
		copy(event.EventTypes, eventTemplate.EventTypes)

		// Try pattern with IP
		pattern1 := regexp.MustCompile(`(?i)(exclusive rights.)\s*(?P<url>http\S*)\s*(?P<ip>\[?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\]?)`)
		if match := pattern1.FindStringSubmatch(body); match != nil {
			event.URL = getURL(match[2])
			event.IP = match[3]
			result = append(result, event)
			foundURLs = true
		} else {
			// Try pattern without IP
			pattern2 := regexp.MustCompile(`(?i)(exclusive rights.)\s*(?P<url>http\S*)`)
			if match := pattern2.FindStringSubmatch(body); match != nil {
				event.URL = getURL(match[2])
				result = append(result, event)
				foundURLs = true
			}
		}
	}

	// If still no URL/IP found, try to find IP
	if !foundURLs {
		event := events.NewEvent(eventTemplate.Parser)
		event.EventDate = eventTemplate.EventDate
		event.EventTypes = make([]events.EventType, len(eventTemplate.EventTypes))
		copy(event.EventTypes, eventTemplate.EventTypes)
		ip := common.FindStringWithoutMarkers(bodyLower, "ip:", "")
		if ip != "" {
			event.IP = ip
			result = append(result, event)
		} else {
			return nil, &common.ParserError{Message: "Couldn't get any ip or url"}
		}
	}

	return result, nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	event := events.NewEvent("puig")
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	subjectLower := strings.ToLower(subject)
	bodyLower := strings.ToLower(body)

	if strings.Contains(subjectLower, "infringement") && strings.Contains(bodyLower, "trademark") {
		dateHeaders, ok := serializedEmail.Headers["date"]
		if !ok || len(dateHeaders) == 0 {
			return nil, &common.ParserError{Message: "date header not found"}
		}

		return parseTrademark(body, event, dateHeaders[0])
	}

	return nil, &common.NewTypeError{Subject: subject}
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
