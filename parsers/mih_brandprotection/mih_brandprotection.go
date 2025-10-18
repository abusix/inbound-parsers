// Package mih_brandprotection implements the MIH Brand Protection parser
package mih_brandprotection

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the mih_brandprotection parser
type Parser struct{}

var (
	externalIDPattern                = regexp.MustCompile(`(?i)\[ecin:(?P<id>\S+)\]`)
	registrationNosPattern           = regexp.MustCompile(`(?i)registration nos\. (?P<no>.+) for the`)
	officialURLPattern               = regexp.MustCompile(`(?i)and services through websites including (?P<official>\S+)`)
	ispURLPattern                    = regexp.MustCompile(`(?i)the internet service provider to (?P<url>\S+)`)
	infringingMaterialURLPattern     = regexp.MustCompile(`(?i)to the infringing material at the following url\(s\):\s+(?P<url>http\S+)`)
	ipPattern                        = regexp.MustCompile(`(?i)ip:\s+(?P<ip>\S+) \.`)
	exactLocationPattern             = regexp.MustCompile(`(?i)the exact location of the infringement is:\s*(?P<url>http\S+)`)
	urlsPattern                      = regexp.MustCompile(`(?i)url\(s\): (?P<url>http\S+)`)
	countryPattern                   = regexp.MustCompile(`(?i)(?P<country>\S+) registration nos\.`)
	trademarkURLsPattern             = regexp.MustCompile(`(?i)url: \.+ (?P<url>http\S+)`)
	websiteLocationPattern           = regexp.MustCompile(`(?i)connected to your website located at (?P<url>http\S+)`)
	noticeOfTrademarkCopyrightPattern = regexp.MustCompile(`(?i)notice of trademark and copyright infringement`)
	noticeOfCopyrightPattern         = regexp.MustCompile(`(?i)notice of copyright infringement`)
	noticeOfTrademarkPattern         = regexp.MustCompile(`(?i)notice of trademark infringement`)
	noticeOfInfringementPattern      = regexp.MustCompile(`(?i)notice of infringement`)
	dearISPPattern                   = regexp.MustCompile(`(?i)dear internet service provider`)
)

// NewParser creates a new mih_brandprotection parser
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from prosus@mih-brandprotection.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Normalize body to lowercase for pattern matching
	bodyLower := strings.ToLower(body)

	// Create base event
	event := events.NewEvent("mih_brandprotection")

	// Set event date
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Extract external ID from subject
	if match := externalIDPattern.FindStringSubmatch(subject); len(match) > 1 {
		externalID := &events.ExternalID{ID: match[1]}
		event.AddEventDetail(externalID)
	}

	// Route to appropriate parser based on subject/body content
	if noticeOfTrademarkCopyrightPattern.MatchString(subject) {
		if noticeOfCopyrightPattern.MatchString(bodyLower) {
			return parseCopyrightInfringement(serializedEmail, body, event)
		}
		return parseTrademarkAndCopyright(serializedEmail, body, event)
	} else if noticeOfTrademarkPattern.MatchString(subject) {
		return parseTrademarkInfringement(serializedEmail, body, event)
	} else if noticeOfInfringementPattern.MatchString(subject) {
		if dearISPPattern.MatchString(bodyLower) {
			return parseTrademarkAndCopyright(serializedEmail, body, event)
		}
		return parseTrademarkInfringement(serializedEmail, body, event)
	} else if noticeOfCopyrightPattern.MatchString(bodyLower) {
		return parseCopyrightInfringement(serializedEmail, body, event)
	}

	return nil, common.NewNewTypeError(subject)
}

func parseTrademarkAndCopyright(serializedEmail *email.SerializedEmail, body string, event *events.Event) ([]*events.Event, error) {
	// Extract trademark owner
	trademarkOwner := common.FindStringWithoutMarkers(body, "uses", "trademark(s) in its domain")
	trademarkOwner = strings.TrimSpace(trademarkOwner)

	// Extract country
	country := common.FindStringWithoutMarkers(body, " are registered worldwide and include:", "Registration Nos.")
	country = strings.TrimSpace(country)

	// Extract registration numbers
	var registrationNumbers []string
	if match := registrationNosPattern.FindStringSubmatch(body); len(match) > 1 {
		numbersStr := match[1]
		registrationNumbers = strings.Split(numbersStr, ",")
		for i := range registrationNumbers {
			registrationNumbers[i] = strings.TrimSpace(registrationNumbers[i])
		}
	}

	// Extract official URL
	officialURL := ""
	if match := officialURLPattern.FindStringSubmatch(body); len(match) > 1 {
		officialURL = match[1]
	}

	// Create trademark event type
	trademark := &events.Trademark{
		BaseEventType: events.BaseEventType{
			Name: "trademark",
			Type: "trademark",
		},
		TrademarkOwner:      trademarkOwner,
		Country:             country,
		RegistrationNumbers: registrationNumbers,
		OfficialURL:         officialURL,
	}
	event.EventTypes = []events.EventType{trademark}

	// Extract URL
	if match := ispURLPattern.FindStringSubmatch(body); len(match) > 1 {
		event.URL = match[1]
	}
	if match := infringingMaterialURLPattern.FindStringSubmatch(body); len(match) > 1 {
		event.URL = match[1]
	}

	// Extract IP
	if match := ipPattern.FindStringSubmatch(body); len(match) > 1 {
		event.IP = match[1]
	}

	return []*events.Event{event}, nil
}

func parseCopyrightInfringement(serializedEmail *email.SerializedEmail, body string, event *events.Event) ([]*events.Event, error) {
	// Extract copyright owner
	copyrightOwner := common.FindStringWithoutMarkers(body, "1.", "a Prosus Services")
	copyrightOwner = strings.TrimSpace(copyrightOwner)

	// Create copyright event type
	copyright := events.NewCopyright("", copyrightOwner, "")
	event.EventTypes = []events.EventType{copyright}

	// Extract URL
	if match := exactLocationPattern.FindStringSubmatch(body); len(match) > 1 {
		event.URL = match[1]
	}
	if match := urlsPattern.FindStringSubmatch(body); len(match) > 1 {
		event.URL = match[1]
	}

	return []*events.Event{event}, nil
}

func parseTrademarkInfringement(serializedEmail *email.SerializedEmail, body string, eventTemplate *events.Event) ([]*events.Event, error) {
	// Extract trademark owner
	trademarkOwner := common.FindStringWithoutMarkers(body, "to you on behalf of", ",")
	trademarkOwner = strings.TrimSpace(trademarkOwner)

	// Extract country
	country := ""
	if match := countryPattern.FindStringSubmatch(body); len(match) > 1 {
		country = match[1]
	}

	// Extract registration numbers
	registrationNumbersStr := common.FindStringWithoutMarkers(body, "Registration Nos. ", " for the")
	var registrationNumbers []string
	if registrationNumbersStr != "" {
		registrationNumbers = strings.Split(registrationNumbersStr, ", ")
	}

	// Create trademark event type
	trademark := &events.Trademark{
		BaseEventType: events.BaseEventType{
			Name: "trademark",
			Type: "trademark",
		},
		TrademarkOwner:      trademarkOwner,
		Country:             country,
		RegistrationNumbers: registrationNumbers,
	}
	eventTemplate.EventTypes = []events.EventType{trademark}

	var eventsToReturn []*events.Event

	// Extract URLs - may have multiple
	matches := trademarkURLsPattern.FindAllStringSubmatch(body, -1)
	if len(matches) > 0 {
		for _, match := range matches {
			if len(match) > 1 {
				// Deep copy event for each URL
				event := events.NewEvent("mih_brandprotection")
				event.EventDate = eventTemplate.EventDate
				event.EventDetails = make([]events.EventDetail, len(eventTemplate.EventDetails))
				copy(event.EventDetails, eventTemplate.EventDetails)

				// Create new trademark with same data
				trademarkCopy := &events.Trademark{
					BaseEventType: events.BaseEventType{
						Name: "trademark",
						Type: "trademark",
					},
					TrademarkOwner:      trademarkOwner,
					Country:             country,
					RegistrationNumbers: registrationNumbers,
				}
				event.EventTypes = []events.EventType{trademarkCopy}
				event.URL = match[1]
				eventsToReturn = append(eventsToReturn, event)
			}
		}
		return eventsToReturn, nil
	}

	// If no URL pattern matches, try website location pattern
	if match := websiteLocationPattern.FindStringSubmatch(body); len(match) > 1 {
		eventTemplate.URL = match[1]
	}

	return []*events.Event{eventTemplate}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
