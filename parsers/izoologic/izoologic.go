package izoologic

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

	// Create base event
	event := events.NewEvent("izoologic")

	// Set event date from email headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		event.EventDate = email.ParseDate(dateHeader[0])
	}

	// Try to extract IP from body
	if ipMatch := regexp.MustCompile(`(?i)ip address(:| :) (\S+)`).FindStringSubmatch(body); ipMatch != nil && len(ipMatch) > 2 {
		event.IP = ipMatch[2]
	}

	var result []*events.Event

	// Check for fraud in subject with URL
	if containsAny(subjectLower, []string{
		"fraudulent website",
		"redirection code removal request",
	}) {
		if url := getURLFromSubject(subject); url != "" {
			event.EventTypes = []events.EventType{events.NewFraud()}
			event.URL = url
			result = append(result, event)
		}
	} else if strings.Contains(subjectLower, "phishing") || strings.Contains(body, "Phishing") {
		// Parse phishing
		result = append(result, parsePhishing(body, subject, event)...)
	} else if containsAny(subjectLower, []string{
		"trademark infringement notice",
		"unauthorized job listing",
	}) {
		// Parse trademark
		result = append(result, parseTrademark(body, event)...)
	} else if containsAny(subjectLower, []string{
		"mobile apps takedown request",
		"mobile app takedown request",
		"unauthorized app removal request",
		"mobile application removal request",
		"application removal assistance request",
		"mobile app removal",
		"private content removal",
		"dmca",
		"intellectual property",
	}) {
		// Parse copyright
		result = append(result, parseCopyright(body, subject, event)...)
	} else if containsAny(subjectLower, []string{
		"fake website",
		"proof of affiliation request",
		"website takedown request",
	}) {
		// Parse fraud
		result = append(result, parseFraud(body, event)...)
	} else if containsAny(subjectLower, []string{"article removal request"}) {
		// Parse harassment (maps to Doxing in Go)
		result = append(result, parseHarassment(body, event)...)
	} else {
		return nil, &common.NewTypeError{Subject: "Unknown izoologic type: " + subjectLower}
	}

	return result, nil
}

func parsePhishing(body, subject string, baseEvent *events.Event) []*events.Event {
	// Clean body
	body = strings.ReplaceAll(body, "Official", "official")
	body = strings.ReplaceAll(body, "login page", "website")

	// Try to find official website
	var officialBlock []string
	if strings.Contains(body, "official Website:") {
		officialBlock = common.GetBlockAround(body, "official Website:")
	} else if strings.Contains(body, "should refer only to their official website") {
		officialBlock = common.GetBlockAround(body, "should refer only to their official website")
	} else if strings.Contains(body, "official website can be") {
		officialBlock = common.GetBlockAround(body, "official website can be")
	} else if strings.Contains(body, "official website and authorized social") {
		officialBlock = common.GetBlockAround(body, "official website and authorized social")
	} else if strings.Contains(body, "official website of") {
		officialBlock = common.GetBlockAround(body, "official website of")
	} else if strings.Contains(body, "Legitimate Website") {
		officialBlock = common.GetBlockAround(body, "Legitimate Website")
	} else {
		officialBlock = common.GetBlockAround(body, "official website")
	}

	officialWebsite := ""
	for _, line := range officialBlock {
		if urlMatch := regexp.MustCompile(`(?P<url>(http|hxxp)\S+)`).FindStringSubmatch(line); urlMatch != nil && len(urlMatch) > 1 {
			officialWebsite = urlMatch[1]
			break
		}
	}

	if officialWebsite == "" {
		officialWebsite = common.GetNonEmptyLineAfter(body, "official website")
	}
	if officialWebsite == "" {
		officialWebsite = common.GetNonEmptyLineAfter(body, "be accessed thru :")
	}
	if officialWebsite == "" {
		officialWebsite = common.GetNonEmptyLineAfter(body, "official Website which can be found at:")
	}

	// Create phishing event
	event := copyEvent(baseEvent)
	if officialWebsite != "" {
		event.EventTypes = []events.EventType{events.NewPhishingWithOfficialURL(officialWebsite)}
	} else {
		event.EventTypes = []events.EventType{events.NewPhishing()}
	}

	// Get URL from subject or body
	if url := getURLFromSubject(subject); url != "" {
		event.URL = url
	} else {
		event.URL = getURLFromBody(body)
	}

	return []*events.Event{event}
}

func parseCopyright(body, subject string, baseEvent *events.Event) []*events.Event {
	copyrightOwner := common.FindStringWithoutMarkers(body, "an authorized representative of our client,", ".")
	if copyrightOwner == "" {
		copyrightOwner = common.FindStringWithoutMarkers(body, "Subsidiary", ".")
	}
	copyrightOwner = strings.TrimSpace(copyrightOwner)

	originalMaterial := common.GetNonEmptyLineAfter(body, "Copyrighted original material:")
	if originalMaterial == "" {
		originalMaterial = common.FindStringWithoutMarkers(body, "Official mobile application:", "")
	}
	if originalMaterial == "" {
		originalMaterial = common.GetNonEmptyLineAfter(body, "official and authorized download link")
	}
	if originalMaterial == "" {
		originalMaterial = strings.Trim(common.FindStringWithoutMarkers(body, "official site of our client is", ""), "\n \r\t-")
	}
	originalMaterial = strings.TrimSpace(originalMaterial)

	// Create copyright event type
	var results []*events.Event

	// Check if URL is in subject
	if url := getURLFromSubject(subject); url != "" {
		event := copyEvent(baseEvent)
		event.EventTypes = []events.EventType{events.NewCopyright(originalMaterial, copyrightOwner, "")}
		event.URL = url
		results = append(results, event)
	} else {
		// Get URL block from body
		var urlBlock []string
		urlBlock = common.GetContinuousLinesUntilEmptyLine(body, "URLs:")
		if len(urlBlock) == 0 {
			urlStr := common.FindStringWithoutMarkers(body, "The unauthorized and infringing copy can be found at:", "The app is")
			urlBlock = strings.Split(urlStr, "\n")
		}
		if len(urlBlock) == 0 {
			line := common.GetNonEmptyLineAfter(body, "Infringing App for removal:")
			if line != "" {
				urlBlock = []string{line}
			}
		}

		for _, url := range urlBlock {
			url = strings.TrimSpace(url)
			if url != "" {
				event := copyEvent(baseEvent)
				event.EventTypes = []events.EventType{events.NewCopyright(originalMaterial, copyrightOwner, "")}
				event.URL = url
				results = append(results, event)
			}
		}
	}

	return results
}

func parseTrademark(body string, baseEvent *events.Event) []*events.Event {
	trademarkOwner := common.FindStringWithoutMarkers(body, "representative of our client", ".")
	if trademarkOwner == "" {
		trademarkOwner = common.FindStringWithoutMarkers(body, "authorized representative of", ".")
	}
	trademarkOwner = strings.TrimSpace(trademarkOwner)

	trademarkedMaterial := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Link:", ""))
	registrationNumber := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Trademark Registration Number:", ""))
	country := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Country/Jurisdiction:", ""))

	officialURLStr := common.FindStringWithoutMarkers(body, "Official Website", "")
	parts := strings.Split(officialURLStr, ": ")
	officialURL := ""
	if len(parts) > 0 {
		officialURL = strings.TrimSpace(parts[len(parts)-1])
	}

	// Create trademark event
	event := copyEvent(baseEvent)

	var registrationNumbers []string
	if registrationNumber != "" {
		registrationNumbers = []string{registrationNumber}
	}

	trademark := events.NewTrademarkWithURL(country, registrationNumbers, trademarkOwner, trademarkedMaterial, officialURL)
	event.EventTypes = []events.EventType{trademark}

	// Find URL
	if urlMatch := regexp.MustCompile(`(?i)unauthorized and infringing copy can be found at: (http\S+)`).FindStringSubmatch(body); urlMatch != nil && len(urlMatch) > 1 {
		event.URL = urlMatch[1]
		return []*events.Event{event}
	} else if url := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Reported URL:", "")); url != "" {
		event.URL = url
		return []*events.Event{event}
	}

	return []*events.Event{event}
}

func parseFraud(body string, baseEvent *events.Event) []*events.Event {
	event := copyEvent(baseEvent)
	event.EventTypes = []events.EventType{events.NewFraud()}

	body = strings.ReplaceAll(body, " :", ":")

	// Try to find URL
	if urlMatch := regexp.MustCompile(`(?i)(url)|(fraudulent website):.*(?P<url>(http|hxxp)\S+)`).FindStringSubmatch(body); urlMatch != nil && len(urlMatch) > 0 {
		for i, name := range regexp.MustCompile(`(?i)(url)|(fraudulent website):.*(?P<url>(http|hxxp)\S+)`).SubexpNames() {
			if name == "url" && i < len(urlMatch) {
				event.URL = urlMatch[i]
				break
			}
		}
	}

	// Try to find IP
	if ipMatch := regexp.MustCompile(`(?i)ip address:\s*(\S+)`).FindStringSubmatch(body); ipMatch != nil && len(ipMatch) > 1 {
		event.IP = ipMatch[1]
	}

	// Try to find event date
	registeredOn := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Registered On:", ""))
	if registeredOn != "" {
		event.EventDate = email.ParseDate(registeredOn)
	}

	return []*events.Event{event}
}

func parseHarassment(body string, baseEvent *events.Event) []*events.Event {
	// In Go, Harassment maps to Doxing event type
	event := copyEvent(baseEvent)
	event.EventTypes = []events.EventType{events.NewDoxing()}

	body = strings.ReplaceAll(body, " :", ":")

	// Try to find URL
	if urlMatch := regexp.MustCompile(`(?i)(url)|(article for removal):.*(?P<url>(http|hxxp)\S+)`).FindStringSubmatch(body); urlMatch != nil && len(urlMatch) > 0 {
		for i, name := range regexp.MustCompile(`(?i)(url)|(article for removal):.*(?P<url>(http|hxxp)\S+)`).SubexpNames() {
			if name == "url" && i < len(urlMatch) {
				event.URL = urlMatch[i]
				break
			}
		}
	}

	// Try to find IP
	if ipMatch := regexp.MustCompile(`(?i)ip address:\s*(\S+)`).FindStringSubmatch(body); ipMatch != nil && len(ipMatch) > 1 {
		event.IP = ipMatch[1]
	}

	return []*events.Event{event}
}

// Helper functions

func getURLFromSubject(subject string) string {
	if urlMatch := regexp.MustCompile(`(?P<url>(http|hxxp)\S+)`).FindStringSubmatch(subject); urlMatch != nil && len(urlMatch) > 1 {
		return urlMatch[1]
	}
	return ""
}

func getURLFromBody(body string) string {
	if urlMatch := regexp.MustCompile(`(?i)url(:| :|\[:]) \S+`).FindStringSubmatch(body); urlMatch != nil && len(urlMatch) > 0 {
		return urlMatch[0]
	} else if urlMatch := regexp.MustCompile(`(?i)for(\s+content|)\s+removal:\s+(http\S+)`).FindStringSubmatch(body); urlMatch != nil && len(urlMatch) > 2 {
		return urlMatch[2]
	}
	return ""
}

func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

func copyEvent(src *events.Event) *events.Event {
	dst := events.NewEvent(src.Parser)
	dst.IP = src.IP
	dst.URL = src.URL
	dst.EventDate = src.EventDate
	return dst
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
