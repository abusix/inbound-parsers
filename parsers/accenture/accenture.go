package accenture

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
)

type Parser struct{}

var (
	urlPattern  = regexp.MustCompile(`(?i)((shutdown of this resource|chiusura di questa risorsa):)(?P<url>.*)`)
	urlPattern2 = regexp.MustCompile(`(?i)((the site is: |following domain: |provider of the resources:))\s*(?P<url>\S*)`)
)

func NewParser() *Parser {
	return &Parser{}
}

func buildURL(url string) string {
	url = strings.ReplaceAll(url, "[.]", ".")
	if !strings.Contains(url, "http") && !strings.Contains(url, "hxxp") {
		return "http://" + url
	}
	return url
}

func parseTrademark(body string, event *events.Event, dateFallback string) ([]*events.Event, error) {
	event.EventDate = email.ParseDate(dateFallback)
	event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}

	if match := urlPattern.FindStringSubmatch(body); len(match) > 0 {
		// Extract named group 'url'
		for i, name := range urlPattern.SubexpNames() {
			if name == "url" && i < len(match) {
				foundURL := strings.ReplaceAll(match[i], "[.]", ".")
				event.URL = buildURL(foundURL)
				return []*events.Event{event}, nil
			}
		}
	}

	return nil, common.NewParserError("couldn't find url")
}

func parsePhishing(body string, event *events.Event, dateFallback string) ([]*events.Event, error) {
	event.EventDate = email.ParseDate(dateFallback)
	event.EventTypes = []events.EventType{events.NewPhishing()}

	if match := urlPattern2.FindStringSubmatch(body); len(match) > 0 {
		// Extract named group 'url'
		for i, name := range urlPattern2.SubexpNames() {
			if name == "url" && i < len(match) {
				foundURL := match[i]
				event.URL = buildURL(foundURL)
				return []*events.Event{event}, nil
			}
		}
	}

	// Alternative: parse URL block
	tag := "following urls:"
	bodyLower := strings.ToLower(body)
	bodyLower = strings.ReplaceAll(bodyLower, tag, tag+"\n")
	urlBlock := common.GetBlockAfterWithStop(bodyLower, tag, "")

	var results []*events.Event
	for _, line := range urlBlock {
		line = strings.ReplaceAll(line, "*   ", "")
		url := buildURL(line)

		// Create a copy of the event for each URL
		eventCopy := *event
		eventCopy.URL = url
		results = append(results, &eventCopy)
	}

	if len(results) > 0 {
		return results, nil
	}

	if event.URL == "" {
		return nil, common.NewParserError("couldn't find url")
	}

	return []*events.Event{event}, nil
}

func parseIPAttack(body string, event *events.Event, dateFallback string) ([]*events.Event, error) {
	event.EventDate = email.ParseDate(dateFallback)
	event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

	tag := "ip address on your ip ranges"
	bodyLower := strings.ToLower(body)
	bodyLower = strings.ReplaceAll(bodyLower, tag, tag+"\n")
	ipBlock := common.GetBlockAfterWithStop(bodyLower, tag, "")

	var results []*events.Event
	for _, line := range ipBlock {
		eventCopy := *event
		ip := common.ExtractOneIP(line)
		if ip == "" {
			return nil, common.NewParserError("Couldn't get the IP")
		}
		eventCopy.IP = ip
		results = append(results, &eventCopy)
	}

	return results, nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	event := events.NewEvent("accenture")
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)
	bodyLower := strings.ToLower(body)

	// Get date from headers
	var dateFallback string
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		dateFallback = dateHeader[0]
	}

	// Determine which type of report this is
	if strings.Contains(subjectLower, "shutdown request") &&
		(strings.Contains(bodyLower, "counterfeit") ||
			strings.Contains(bodyLower, "trademark") ||
			strings.Contains(bodyLower, "brand abuse")) {
		return parseTrademark(body, event, dateFallback)
	} else if (strings.Contains(subjectLower, "takedown request") ||
		strings.Contains(subjectLower, "abuse reporting")) &&
		strings.Contains(bodyLower, "phishing") ||
		strings.Contains(subjectLower, "phishing") {
		return parsePhishing(body, event, dateFallback)
	} else if strings.Contains(subjectLower, "attack from your ips") {
		return parseIPAttack(body, event, dateFallback)
	}

	return nil, common.NewParserError("unknown email type: " + subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
