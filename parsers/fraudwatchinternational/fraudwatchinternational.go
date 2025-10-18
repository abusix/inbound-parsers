package fraudwatchinternational

import (
	"fmt"
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

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		subject = ""
	}

	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)

	// Extract external ID from body or subject
	exID := common.FindStringWithoutMarkers(body, "Incident", "]")
	if exID == "" {
		exID = common.FindStringWithoutMarkers(subject, "Incident", "]")
	}
	externalID := &events.ExternalID{ID: exID}

	// Get date from email header
	var eventDate *string
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = &dateHeaders[0]
	}

	// Route to appropriate parser based on subject keywords
	if strings.Contains(subjectLower, "trademark") ||
		(strings.Contains(subjectLower, "domain suspension request") && strings.Contains(bodyLower, "trademark")) {
		return parseTrademark(body, bodyLower, eventDate, externalID)
	} else if strings.Contains(subjectLower, "copyright") || strings.Contains(subjectLower, "dmca") {
		return parseCopyright(body, bodyLower, eventDate, externalID)
	} else if strings.Contains(subjectLower, "fraudulent") {
		return parseMaliciousEmail(body, bodyLower, eventDate, externalID)
	} else if strings.Contains(subjectLower, "malicious") || strings.Contains(subjectLower, "email fraud") {
		return parseMalicious(body, bodyLower, eventDate, externalID)
	}

	// Default phishing parser
	return parsePhishing(body, bodyLower, eventDate, externalID)
}

func getReporter(body string) *events.Organisation {
	bodyLower := strings.ToLower(body)
	reporter := &events.Organisation{}

	// Extract contact name
	var contactFirstName, contactLastName string
	if strings.Contains(bodyLower, "requestor first name:") {
		contactFirstName = strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "requestor first name:", ""))
	}
	if strings.Contains(bodyLower, "requestor last name:") {
		contactLastName = strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "requestor last name:", ""))
	}
	reporter.ContactName = strings.TrimSpace(contactFirstName + " " + contactLastName)

	// Extract contact email
	var contactEmail string
	if strings.Contains(bodyLower, "e-mail:") {
		contactEmail = strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "e-mail:", ""))
	} else if strings.Contains(bodyLower, "e-mail address:") {
		contactEmail = strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "e-mail address:", ""))
	} else if strings.Contains(bodyLower, "email:") {
		contactEmail = strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "email:", ""))
	}
	reporter.ContactEmail = contactEmail

	// Extract contact phone
	var contactPhone string
	if strings.Contains(bodyLower, "phone number:") {
		contactPhone = strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "phone number:", ""))
	} else if strings.Contains(bodyLower, "phone:") {
		contactPhone = strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "phone:", ""))
	}
	reporter.ContactPhone = contactPhone

	// Extract address
	if strings.Contains(bodyLower, "mailing address:") {
		reporter.Address = strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "mailing address:", ""))
	} else {
		var contactAddress, contactCountry, contactState, contactCity string
		if strings.Contains(bodyLower, "street address:") {
			contactAddress = strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "street address:", ""))
		}
		if strings.Contains(bodyLower, "city:") {
			contactCity = strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "city:", ""))
		}
		if strings.Contains(bodyLower, "state/province:") {
			contactState = strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "state/province:", ""))
		}
		if strings.Contains(bodyLower, "country:") {
			contactCountry = strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "country:", ""))
		}
		reporter.Address = fmt.Sprintf("%s (%s - %s - %s)", contactAddress, contactCountry, contactState, contactCity)
	}

	// Extract website URL
	if strings.Contains(bodyLower, "web:") {
		reporter.URLOrDomain = strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "web:", ""))
	}

	return reporter
}

func parseTrademark(body, bodyLower string, eventDate *string, externalID *events.ExternalID) ([]*events.Event, error) {
	var evts []*events.Event

	// Extract trademark details
	trademarkRegNumber := strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "trademark registration number:", ""))
	trademarkName := strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "trademark name:", ""))
	markOwner := strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "mark owner:", ""))

	trademark := events.NewTrademark("", []string{trademarkRegNumber}, markOwner, trademarkName)

	// Extract mark listing evidence
	markListing := strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "direct link to mark listing:", ""))
	evidence := &events.Evidence{}
	if markListing != "" {
		evidence.AddEvidence(events.UrlStore{
			Description: "mark_listing",
			URL:         markListing,
		})
	}

	reporter := getReporter(body)

	// Extract infringing links
	var infringingLinks []string
	if urls := common.GetContinuousLinesUntilEmptyLine(bodyLower, "direct links to infringing content:"); len(urls) > 0 {
		infringingLinks = urls
	} else if urls := common.GetContinuousLinesUntilEmptyLine(bodyLower, "domains:"); len(urls) > 0 {
		infringingLinks = urls
	} else {
		infringingLinks = common.GetContinuousLinesUntilEmptyLine(bodyLower, "offending urls:")
	}

	ip := strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "ip address:", ""))

	// Create event for each infringing URL
	for _, url := range infringingLinks {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}

		event := events.NewEvent("fraudwatchinternational")
		event.URL = url
		event.IP = ip
		if eventDate != nil {
			event.EventDate = email.ParseDate(*eventDate)
		}
		event.EventTypes = []events.EventType{trademark}
		event.AddEventDetail(evidence)
		event.AddEventDetail(reporter)
		event.AddEventDetail(externalID)
		evts = append(evts, event)
	}

	return evts, nil
}

func parseCopyright(body, bodyLower string, eventDate *string, externalID *events.ExternalID) ([]*events.Event, error) {
	var evts []*events.Event

	// Extract infringing links
	infringingLinks := common.GetContinuousLinesUntilEmptyLine(
		bodyLower, "infringing material is located at the following url",
	)
	if len(infringingLinks) == 0 {
		return nil, common.NewParserError("infringing urls not found")
	}

	// Extract original material URLs
	originalMaterials := common.GetContinuousLinesUntilEmptyLine(
		bodyLower, "original material is located at the following url",
	)

	reporter := getReporter(body)

	// Create event for each infringing URL
	for _, url := range infringingLinks {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}

		event := events.NewEvent("fraudwatchinternational")
		event.URL = url
		if eventDate != nil {
			event.EventDate = email.ParseDate(*eventDate)
		}
		event.AddEventDetail(reporter)
		event.AddEventDetail(externalID)

		// Create Copyright event type with official URLs
		copyright := events.NewCopyright("", "", "")
		// Note: In Python, there's a TListStore for official_urls
		// In Go, we'll set the OfficialURL to the first one if available
		if len(originalMaterials) > 0 {
			copyright.OfficialURL = strings.TrimSpace(originalMaterials[0])
		}
		event.EventTypes = []events.EventType{copyright}

		evts = append(evts, event)
	}

	return evts, nil
}

func parseMalicious(body, bodyLower string, eventDate *string, externalID *events.ExternalID) ([]*events.Event, error) {
	event := events.NewEvent("fraudwatchinternational")
	if eventDate != nil {
		event.EventDate = email.ParseDate(*eventDate)
	}

	brand := strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "brand targeted:", ""))
	event.AddEventDetail(&events.Target{Brand: brand})
	event.AddEventDetail(externalID)
	event.AddEventDetail(getReporter(body))

	serverAddress := strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "mail server address:", ""))
	if serverAddress == "" {
		event.URL = getLineAfter(bodyLower, "ip address:")
		event.IP = common.FindStringWithoutMarkers(bodyLower, "please note that:", "")
	} else {
		if strings.Contains(serverAddress, "[") {
			parts := strings.Split(serverAddress, "[")
			event.URL = parts[0]
			if len(parts) > 1 {
				ipPart := strings.Split(parts[1], "]")
				if len(ipPart) > 0 {
					event.IP = ipPart[0]
				}
			}
		} else {
			event.URL = serverAddress
		}
	}

	event.EventTypes = []events.EventType{events.NewFraud()}

	return []*events.Event{event}, nil
}

func parseMaliciousEmail(body, bodyLower string, eventDate *string, externalID *events.ExternalID) ([]*events.Event, error) {
	event := events.NewEvent("fraudwatchinternational")
	if eventDate != nil {
		event.EventDate = email.ParseDate(*eventDate)
	}
	event.AddEventDetail(externalID)

	emailAddr := common.FindStringWithoutMarkers(bodyLower, "email address:", "")
	if emailAddr == "" {
		emailAddr = common.FindStringWithoutMarkers(bodyLower, "the email address", "")
	}

	ip := common.ExtractOneIP(emailAddr)
	event.IP = ip
	event.EventTypes = []events.EventType{events.NewFraud()}

	// Extract just the email address (first token)
	emailParts := strings.Fields(strings.TrimSpace(emailAddr))
	if len(emailParts) > 0 {
		event.AddEventDetail(&events.Email{FromAddress: emailParts[0]})
	}

	return []*events.Event{event}, nil
}

func parsePhishing(body, bodyLower string, eventDate *string, externalID *events.ExternalID) ([]*events.Event, error) {
	event := events.NewEvent("fraudwatchinternational")

	if eventDate != nil {
		event.EventDate = email.ParseDate(*eventDate)
	}

	event.IP = common.FindStringWithoutMarkers(bodyLower, "ip address: ", "\n")

	phishingURL := common.FindStringWithoutMarkers(bodyLower, "url: ", "\n")
	if phishingURL == "" {
		phishingURL = "http" + common.FindStringWithoutMarkers(bodyLower, "hxxp", "")
	}
	phishingURL = common.CleanURL(phishingURL)
	event.URL = phishingURL

	phishing := events.NewPhishing()
	phishing.PhishingTarget = phishingURL
	event.EventTypes = []events.EventType{phishing}
	event.AddEventDetail(externalID)

	return []*events.Event{event}, nil
}

// getLineAfter is a helper to get the line after a marker (simplified version for this parser)
func getLineAfter(text, marker string) string {
	idx := strings.Index(text, marker)
	if idx == -1 {
		return ""
	}

	// Move past the marker
	remaining := text[idx+len(marker):]

	// Find the first newline
	newlineIdx := strings.Index(remaining, "\n")
	if newlineIdx == -1 {
		return strings.TrimSpace(remaining)
	}

	// Get the line after the marker
	line := remaining[:newlineIdx]
	return strings.TrimSpace(line)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
