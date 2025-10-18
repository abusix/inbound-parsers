package fraudwatch

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

	subjectLower := strings.ToLower(subject)

	// Extract event date from headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	// Extract external ID from subject
	var externalID string
	re := regexp.MustCompile(`\[?incident[:#] ?(?P<id>\w+-\d+)\]?`)
	matches := re.FindStringSubmatch(subjectLower)
	if len(matches) > 1 {
		externalID = matches[1]
	}

	// Route to appropriate parsing function based on subject
	if strings.Contains(subjectLower, "trademark infringement") || strings.Contains(subjectLower, "wordmark infringement") {
		return parseTrademark(strings.ToLower(body), eventDate, externalID)
	} else if strings.Contains(subjectLower, "phishing") ||
		strings.Contains(subjectLower, "brand abuse") ||
		strings.Contains(subjectLower, "domain suspension request") ||
		strings.Contains(subjectLower, "brand infringement") ||
		strings.Contains(subjectLower, "scam") ||
		strings.Contains(subjectLower, "fraudulent site") ||
		(strings.Contains(strings.ToLower(body), "impersonating our client") && !strings.Contains(subjectLower, "malicious email address")) {
		return parsePhishing(strings.ToLower(body), eventDate, externalID)
	} else if strings.Contains(subjectLower, "malicious email address") {
		return parseMaliciousActivity(body, eventDate, externalID)
	} else if strings.Contains(subjectLower, "dmca") || strings.Contains(subjectLower, "app removal request") {
		return parseCopyright(strings.ToLower(body), eventDate, externalID)
	}

	return nil, common.NewParserError("unknown subject type: " + subject)
}

func parseTrademark(body string, eventDate *time.Time, externalID string) ([]*events.Event, error) {
	trademarkName := strings.TrimSpace(strings.Trim(common.FindStringWithoutMarkers(body, "trademark name:", ""), " <>"))
	trademarkOwner := strings.TrimSpace(strings.Trim(common.FindStringWithoutMarkers(body, "mark owner:", ""), " <>"))
	registrationNumber := strings.TrimSpace(strings.Trim(common.FindStringWithoutMarkers(body, "registration number:", ""), " <>"))

	// One \n to put infringing urls onto next line if they are on same line as marker
	// and another \n to add empty line between marker and urls
	body = strings.ReplaceAll(body, "infringing content:", "infringing content:\n\n")
	infringingURLs := common.GetBlockAfterWithStop(body, "infringing content:", "")
	if len(infringingURLs) == 0 {
		return nil, common.NewParserError("did not find infringing urls")
	}

	body = strings.ReplaceAll(body, "legitimate brand url's:", "legitimate brand url's:\n")
	officialURLs := common.GetBlockAfterWithStop(body, "legitimate brand url's:", "")
	var officialURL string
	for _, url := range officialURLs {
		officialURL = strings.Trim(url, " -")
		break
	}

	var result []*events.Event
	for _, infringingURL := range infringingURLs {
		event := events.NewEvent("fraudwatch")
		event.URL = infringingURL
		event.EventDate = eventDate

		// Create trademark event type with registration numbers as array
		var registrationNumbers []string
		if registrationNumber != "" {
			registrationNumbers = []string{registrationNumber}
		}

		trademark := &events.Trademark{
			BaseEventType: events.BaseEventType{
				Name: "trademark",
				Type: "trademark",
			},
			TrademarkOwner:      trademarkOwner,
			OfficialURL:         officialURL,
			RegistrationNumbers: registrationNumbers,
			TrademarkedMaterial: trademarkName,
		}
		event.EventTypes = []events.EventType{trademark}

		if externalID != "" {
			event.AddEventDetail(&events.ExternalID{ID: externalID})
		}

		result = append(result, event)
	}

	return result, nil
}

func parsePhishing(body string, eventDate *time.Time, externalID string) ([]*events.Event, error) {
	ip := strings.TrimSpace(common.FindStringWithoutMarkers(body, "ip address:", ""))

	brand := common.FindStringWithoutMarkers(body, "brand phished:", "")
	if brand == "" {
		brand = common.FindStringWithoutMarkers(body, "customers of our client, ", "")
	}
	if brand == "" {
		brand = common.FindStringWithoutMarkers(body, "impersonating our client ", ":")
	}
	if brand == "" {
		brand = common.FindStringWithoutMarkers(body, "our client's brand and name \"", "\"")
	}
	brand = strings.TrimSpace(brand)

	body = strings.ReplaceAll(body, "phishing content:", "phishing content:\n")
	body = strings.ReplaceAll(body, "urls:", "urls:\n")
	body = strings.ReplaceAll(body, "malicious content:", "malicious content:\n")
	body = strings.ReplaceAll(body, "abusive content:", "abusive content:\n")
	body = strings.ReplaceAll(body, "infringing content:", "infringing content:\n")

	var phishingURLs []string
	phishingURLs = common.GetBlockAfterWithStop(body, "phishing content:", "")
	if len(phishingURLs) == 0 {
		phishingURLs = common.GetBlockAfterWithStop(body, "urls:", "")
	}
	if len(phishingURLs) == 0 {
		phishingURLs = common.GetBlockAfterWithStop(body, "malicious content:", "")
	}
	if len(phishingURLs) == 0 {
		phishingURLs = common.GetBlockAfterWithStop(body, "abusive content:", "")
	}
	if len(phishingURLs) == 0 {
		phishingURLs = common.GetBlockAfterWithStop(body, "impersonating our client", "")
	}
	if len(phishingURLs) == 0 {
		phishingURLs = common.GetBlockAfterWithStop(body, "direct links to infringing content:", "")
	}
	if len(phishingURLs) == 0 {
		return nil, common.NewParserError("did not find phishing urls")
	}

	body = strings.ReplaceAll(body, "legitimate brand url's:", "legitimate brand url's:\n")
	officialURLs := common.GetBlockAfterWithStop(body, "legitimate brand url's:", "")
	var officialURL string
	for _, url := range officialURLs {
		officialURL = strings.Trim(url, " -")
		break
	}

	var result []*events.Event
	for _, phishingURL := range phishingURLs {
		event := events.NewEvent("fraudwatch")
		cleanURL := strings.ReplaceAll(phishingURL, " ", "")
		event.URL = cleanURL

		// Set IP if valid
		if ip != "" {
			if validIP := common.IsIP(ip); validIP != "" {
				event.IP = validIP
			}
		}

		event.EventDate = eventDate

		phishing := &events.Phishing{
			BaseEventType: events.BaseEventType{
				Name: "phishing",
				Type: "phishing",
			},
			PhishingTarget: cleanURL,
			OfficialURL:    officialURL,
		}
		event.EventTypes = []events.EventType{phishing}

		if externalID != "" {
			event.AddEventDetail(&events.ExternalID{ID: externalID})
		}
		if brand != "" {
			event.AddEventDetailSimple("brand", brand)
		}

		result = append(result, event)
	}

	return result, nil
}

func parseCopyright(body string, eventDate *time.Time, externalID string) ([]*events.Event, error) {
	body = strings.ReplaceAll(body, "located at the following urls:", "located at the following urls:\n\n")
	infringingURLs := common.GetBlockAfterWithStop(body, "infringing material is located at", "")
	if len(infringingURLs) == 0 {
		body = strings.ReplaceAll(body, "infringing content:", "infringing content:\n")
		infringingURLs = common.GetBlockAfterWithStop(body, "infringing content:", "")
		if len(infringingURLs) == 0 {
			return nil, common.NewParserError("did not find infringing urls")
		}
	}

	officialURLs := common.GetBlockAfterWithStop(body, "original material is located at", "")
	var officialURL string
	for _, url := range officialURLs {
		officialURL = url
		break
	}

	body = strings.ReplaceAll(body, "brand abused:", "brand abused:\n")
	copyrightOwner := common.GetLineAfter(body, "copyright owner:", 1)
	if copyrightOwner == "" {
		copyrightOwner = common.GetLineAfter(body, "client information:", 1)
	}
	if copyrightOwner == "" {
		copyrightOwner = common.GetLineAfter(body, "brand abused:", 1)
	}
	copyrightOwner = strings.TrimSpace(copyrightOwner)
	if copyrightOwner == "" {
		return nil, common.NewParserError("did not find copyright owner")
	}

	var result []*events.Event
	for _, infringingURL := range infringingURLs {
		event := events.NewEvent("fraudwatch")
		event.URL = infringingURL
		event.EventDate = eventDate

		copyright := &events.Copyright{
			BaseEventType: events.BaseEventType{
				Name: "copyright",
				Type: "copyright",
			},
			CopyrightOwner: copyrightOwner,
			OfficialURL:    officialURL,
		}
		event.EventTypes = []events.EventType{copyright}

		if externalID != "" {
			event.AddEventDetail(&events.ExternalID{ID: externalID})
		}

		result = append(result, event)
	}

	return result, nil
}

func parseMaliciousActivity(body string, eventDate *time.Time, externalID string) ([]*events.Event, error) {
	var eventURL string
	for _, line := range strings.Split(body, "\n") {
		url := common.FindStringWithoutMarkers(line, "email address", "is currently being used")
		if url != "" && strings.Contains(url, "http") {
			eventURL = url
			break
		}
	}

	receivedHeaders := getReceivedHeaders(body)
	if len(receivedHeaders) <= 1 {
		return nil, common.NewParserError("not enough received headers")
	}

	// Discard the first Received address
	relevantRcvHeaders := receivedHeaders[1:]

	var result []*events.Event
	for i, rcv := range relevantRcvHeaders {
		event := events.NewEvent("fraudwatch")
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}

		if externalID != "" {
			event.AddEventDetail(&events.ExternalID{ID: externalID})
		}

		// Try to extract IP from received header
		for _, line := range strings.Split(rcv, "\n") {
			if validIP := common.ExtractOneIP(line); validIP != "" {
				event.IP = validIP
				break
			}
		}

		// Parse date from received header
		rcvDate := parseReceivedDate(rcv)
		if rcvDate != nil {
			event.EventDate = rcvDate
		} else {
			event.EventDate = eventDate
		}

		if eventURL != "" {
			event.URL = eventURL
		}

		// Only add event if we have a URL or IP
		if event.URL != "" || event.IP != "" {
			result = append(result, event)
		}

		// Stop after processing the first relevant header with an IP
		if event.IP != "" {
			break
		}

		// Safety: limit to first 5 headers
		if i >= 4 {
			break
		}
	}

	if len(result) == 0 {
		return nil, common.NewParserError("no events created from malicious activity")
	}

	return result, nil
}

func getReceivedHeaders(body string) []string {
	var bodyLines []string
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "Received:") {
			bodyLines = append(bodyLines, "\nRECEIVED_MARKER\n"+line)
		} else {
			bodyLines = append(bodyLines, line)
		}
	}

	newBody := strings.Join(bodyLines, "\n")
	parts := strings.Split(newBody, "\nRECEIVED_MARKER\n")

	var received []string
	for _, part := range parts {
		if strings.Contains(part, "Received:") {
			received = append(received, part)
		}
	}

	return received
}

func parseReceivedDate(receivedHeader string) *time.Time {
	parts := strings.Split(receivedHeader, ";")
	if len(parts) < 2 {
		return nil
	}

	dateStr := strings.TrimSpace(parts[1])
	return email.ParseDate(dateStr)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
