package phishfort

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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)

	// Create event template
	eventTemplate := events.NewEvent("phishfort")
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventTemplate.EventDate = email.ParseDate(dateHeader[0])
	}

	// Determine parsing path based on subject
	phishingKeywords := []string{
		"phishing takedown request",
		"phishing domain takedown request",
		"phishing takedown",
	}
	for _, keyword := range phishingKeywords {
		if strings.Contains(subjectLower, keyword) {
			return p.parsePhishing(serializedEmail, body, subject, eventTemplate)
		}
	}

	trademarkKeywords := []string{
		"trademark infringement",
		"infringement in relation to",
		"trademark takedown",
	}
	for _, keyword := range trademarkKeywords {
		if strings.Contains(subjectLower, keyword) {
			return p.parseTrademark(body, eventTemplate)
		}
	}

	// Check body for phishing indicators
	if strings.Contains(body, "phishing attack") || strings.Contains(body, "unauthorized app impersonating our client") {
		return p.parsePhishing(serializedEmail, body, subject, eventTemplate)
	}

	return nil, common.NewNewTypeError(subjectLower)
}

func (p *Parser) parsePhishing(serializedEmail *email.SerializedEmail, body, subject string, eventTemplate *events.Event) ([]*events.Event, error) {
	eventTemplate.EventTypes = []events.EventType{events.NewPhishing()}
	subject = strings.ReplaceAll(subject, "\n", "")

	var eventList []*events.Event

	// Case 1: URLs: block
	if strings.Contains(body, "URLs:") {
		urlBlock := common.FindStringWithoutMarkers(body, "URLs:", "As you will notice the scams")
		for _, line := range strings.Split(urlBlock, "\n") {
			if strings.HasPrefix(line, "hxxp") {
				event := p.copyEvent(eventTemplate)
				event.URL = strings.ReplaceAll(line, " ", "")
				eventList = append(eventList, event)
			}
		}
		if len(eventList) > 0 {
			return eventList, nil
		}
	}

	// Case 2: Subject line pattern
	urlPattern := regexp.MustCompile(`(?i)takedown\s*(request\s*)?(for)?\s*(?P<url>.*)`)
	if match := urlPattern.FindStringSubmatch(subject); match != nil {
		urlIdx := urlPattern.SubexpIndex("url")
		if urlIdx != -1 && urlIdx < len(match) {
			url := match[urlIdx]
			eventTemplate.URL = regexp.MustCompile(`\s`).ReplaceAllString(url, "")

			// Try to find IP address
			ipPattern := regexp.MustCompile(`(?i)the phishing site's ip address is (?P<ip>\S+)`)
			if ipMatch := ipPattern.FindStringSubmatch(body); ipMatch != nil {
				ipIdx := ipPattern.SubexpIndex("ip")
				if ipIdx != -1 && ipIdx < len(ipMatch) {
					eventTemplate.IP = ipMatch[ipIdx]
				}
			} else {
				// Try alternative IP extraction
				ip := common.FindStringWithoutMarkers(body, "IP address", "")
				if ip != "" {
					eventTemplate.IP = ip
				}
			}

			return []*events.Event{eventTemplate}, nil
		}
	}

	// Case 3: App link pattern
	if appURL := common.FindStringWithoutMarkers(body, "The app can be found here:", "Our client has"); appURL != "" {
		eventTemplate.URL = regexp.MustCompile(`\s`).ReplaceAllString(appURL, "")
		return []*events.Event{eventTemplate}, nil
	}

	// Case 4: URL: line pattern
	if strings.Contains(body, "URL:") {
		url := common.GetNonEmptyLineAfter(body, "URL:")
		eventTemplate.URL = url
		return []*events.Event{eventTemplate}, nil
	}

	// If we got here and didn't find a URL, it's a new type
	if serializedEmail.Headers != nil {
		if identifier, ok := serializedEmail.Headers["message-id"]; ok && len(identifier) > 0 {
			return nil, common.NewNewTypeError(identifier[0])
		}
	}
	return nil, common.NewNewTypeError(subject)
}

func (p *Parser) parseTrademark(body string, event *events.Event) ([]*events.Event, error) {
	trademarkOwner := strings.TrimSpace(
		common.FindStringWithoutMarkers(body, " on behalf of our client,", ". It has"),
	)
	originalMaterial := strings.TrimSpace(
		common.FindStringWithoutMarkers(body, "original material of our client is at:", ""),
	)
	registrationNumber := strings.TrimSpace(
		common.FindStringWithoutMarkers(body, "TM Registration Number:", ""),
	)

	// Build registration numbers array
	var registrationNumbers []string
	if registrationNumber != "" {
		registrationNumbers = append(registrationNumbers, registrationNumber)
	}

	event.EventTypes = []events.EventType{
		events.NewTrademarkWithURL("", registrationNumbers, trademarkOwner, "", originalMaterial),
	}

	// Extract infringing URL
	modifiedBody := strings.ReplaceAll(body, "found at:", "at:")
	modifiedBody = strings.ReplaceAll(modifiedBody, "And the", "The")
	url := common.FindStringWithoutMarkers(
		modifiedBody,
		"The infringing material is at:",
		"The original material",
	)
	event.URL = regexp.MustCompile(`\s`).ReplaceAllString(url, "")

	return []*events.Event{event}, nil
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
