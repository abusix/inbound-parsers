package sidnnl

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

	subjectLower := strings.ToLower(subject)

	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Create event template
	eventTemplate := events.NewEvent("sidnnl")
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventTemplate.EventDate = email.ParseDate(dateHeader[0])
	}

	// Determine event type from subject
	if p.containsAny(subjectLower, []string{"phishing", "shopping site skimmer", "survey scam"}) {
		eventTemplate.EventTypes = []events.EventType{events.NewPhishing()}
	} else if strings.Contains(subjectLower, "malware") {
		eventTemplate.EventTypes = []events.EventType{events.NewMalware("")}
	} else if p.containsAny(subjectLower, []string{"fake shop", "package scam"}) {
		eventTemplate.EventTypes = []events.EventType{events.NewFraud()}
	} else if strings.Contains(subjectLower, "defaced website") {
		eventTemplate.EventTypes = []events.EventType{events.NewDefacement()}
	} else if strings.Contains(subjectLower, "web shell detected") {
		eventTemplate.EventTypes = []events.EventType{events.NewBackdoor()}
	} else {
		return nil, common.NewNewTypeError(subjectLower)
	}

	// Clean up body text
	body = strings.ReplaceAll(body, "page(s)", "page")
	body = strings.ReplaceAll(body, "pages", "page")
	body = strings.ReplaceAll(body, "Fake game scams", "Extensive information")

	// Extract URLs from the body
	urlBlock := common.FindStringWithoutMarkers(body, "the following page:", "Extensive information")
	urlSet := make(map[string]bool)

	for _, line := range strings.Split(urlBlock, "\n") {
		line = strings.TrimSpace(common.CleanURL(line))
		if common.IsURL(line) {
			urlSet[line] = true
		}
	}

	// Fallback: check subject for URL pattern
	if len(urlSet) == 0 {
		urlPattern := regexp.MustCompile(`under\s+(?P<url>\S+)`)
		if match := urlPattern.FindStringSubmatch(subject); match != nil {
			urlIdx := urlPattern.SubexpIndex("url")
			if urlIdx != -1 && urlIdx < len(match) {
				urlSet[match[urlIdx]] = true
			}
		}
	}

	// Create events for each URL
	var eventList []*events.Event
	for url := range urlSet {
		event := p.copyEvent(eventTemplate)

		// Check if URL contains IP in brackets: url [ip]
		ipPattern := regexp.MustCompile(`(?P<url>\S+)\s*\[(?P<ip>\S+)\]`)
		if match := ipPattern.FindStringSubmatch(url); match != nil {
			urlIdx := ipPattern.SubexpIndex("url")
			ipIdx := ipPattern.SubexpIndex("ip")
			if urlIdx != -1 && urlIdx < len(match) && ipIdx != -1 && ipIdx < len(match) {
				event.URL = match[urlIdx]
				event.IP = match[ipIdx]
			}
		} else {
			event.URL = url
		}

		eventList = append(eventList, event)
	}

	return eventList, nil
}

// containsAny checks if text contains any of the given substrings
func (p *Parser) containsAny(text string, substrings []string) bool {
	for _, substr := range substrings {
		if strings.Contains(text, substr) {
			return true
		}
	}
	return false
}

// copyEvent creates a deep copy of an event
func (p *Parser) copyEvent(src *events.Event) *events.Event {
	dst := events.NewEvent(src.Parser)
	dst.IP = src.IP
	dst.URL = src.URL
	dst.Port = src.Port
	dst.Domain = src.Domain
	dst.ReportID = src.ReportID
	dst.EventDate = src.EventDate
	dst.EventTypes = make([]events.EventType, len(src.EventTypes))
	copy(dst.EventTypes, src.EventTypes)
	return dst
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
