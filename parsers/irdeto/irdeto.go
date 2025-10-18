package irdeto

import (
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

	bodyLower := strings.ToLower(body)

	// Create event template
	eventTemplate := events.NewEvent("irdeto")

	// Parse event date
	dateStr := common.FindStringWithoutMarkers(bodyLower, "was present on", ".")
	dateStr = strings.TrimSpace(dateStr)
	eventDate := email.ParseDate(dateStr)

	// Fallback to header date if parsing failed
	if eventDate == nil {
		if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
			eventDate = email.ParseDate(dateHeader[0])
		}
	}
	eventTemplate.EventDate = eventDate

	// Determine copyright owner and extract relevant information
	var infringingStart string
	var infringingStops []string

	if strings.Contains(bodyLower, "disney enterprise") {
		// Disney Enterprises case
		copyrightedWork := common.GetNonEmptyLineAfter(bodyLower, "copyrighted work(s) infringed upon:")
		eventTemplate.EventTypes = []events.EventType{
			events.NewCopyright(copyrightedWork, "Disney Enterprises, Inc.", ""),
		}
		infringingStart = "location of infringing material:"
		infringingStops = []string{
			"important notes for infringing material:",
			"i have a good faith belief",
		}
	} else if strings.Contains(bodyLower, "epic games inc") {
		// Epic Games case
		officialURLs := common.FindStringWithoutMarkers(bodyLower, "reference websites:", "the reported domain")
		officialURL := ""
		for _, line := range strings.Split(officialURLs, "\n") {
			line = strings.Trim(line, "\n\t\r *")
			if common.IsURL(line) {
				officialURL = line
				break
			}
		}

		trademark := &events.Trademark{
			BaseEventType: events.BaseEventType{
				Name: "trademark",
				Type: "trademark",
			},
			TrademarkOwner: "Epic Games, Inc.",
			OfficialURL:    officialURL,
		}
		eventTemplate.EventTypes = []events.EventType{trademark}
		infringingStart = "the reported domain is not authorized by epic games"
		infringingStops = []string{"we respectfully request that the owner"}
	} else if strings.Contains(bodyLower, "conmebol") {
		// CONMEBOL case
		eventTemplate.EventTypes = []events.EventType{
			events.NewCopyright("", "CONMEBOL", ""),
		}
		infringingStart = "the infringing material subject to this copyright complaint is located:"
		infringingStops = []string{"we respectfully request that the owner"}
	} else {
		return nil, common.NewParserError("unknown copyright owner")
	}

	// Extract IP address
	ip := common.FindStringWithoutMarkers(bodyLower, "ip address", "")
	ip = strings.TrimSpace(ip)
	// Extract just the IP if there's more text
	if ipExtracted := common.ExtractOneIP(ip); ipExtracted != "" {
		eventTemplate.IP = ipExtracted
	}

	// Find location info using appropriate stop marker
	locationInfo := ""
	infringingStop := ""
	for _, stop := range infringingStops {
		locationInfo = common.FindStringWithoutMarkers(bodyLower, infringingStart, stop)
		if locationInfo != "" {
			infringingStop = stop
			break
		}
	}

	// Extract URLs from location info
	var events []*events.Event
	for _, line := range strings.Split(locationInfo, "\n") {
		line = strings.Trim(line, "\n\t\r *")
		if common.IsURL(line) {
			// Create a copy of the event template
			event := *eventTemplate
			event.URL = line
			events = append(events, &event)
		}
		if infringingStop != "" && strings.Contains(line, infringingStop) {
			break
		}
	}

	if len(events) == 0 {
		return nil, common.NewParserError("no URLs found in infringing material section")
	}

	return events, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
