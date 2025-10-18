package cert_nz

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
	// Get body and subject (throws=true)
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, &common.ParserError{Message: "email body is empty"}
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, &common.ParserError{Message: "subject header not found"}
	}

	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)

	// Extract incident ID from subject
	incidentID := common.FindStringWithoutMarkers(subjectLower, "incident", "")
	incidentID = strings.TrimSpace(incidentID)

	// Find URLs - look for hxxp patterns first
	urlPattern := regexp.MustCompile(`hxxp[^\s]*`)
	urls := urlPattern.FindAllString(bodyLower, -1)

	// If no hxxp URLs found, try alternative patterns
	if len(urls) == 0 {
		// Try "targeting new zealanders:" pattern
		if url := common.GetNonEmptyLineAfter(bodyLower, "targeting new zealanders:"); url != "" {
			urls = []string{url}
		} else if url := common.FindStringWithoutMarkers(bodyLower, "domain:", ""); url != "" {
			// Strip trailing /* characters
			url = strings.TrimRight(url, "/*")
			urls = []string{url}
		}
	}

	// Extract IP address
	ip := common.ExtractOneIP(bodyLower)

	// Extract date - look for "utc:" pattern first
	var dateStr string
	utcPattern := regexp.MustCompile(`utc:[^\]\)]*`)
	utcMatches := utcPattern.FindAllString(bodyLower, -1)
	if len(utcMatches) > 0 {
		dateStr = utcMatches[0]
	} else {
		// Fallback to email date header
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			dateStr = dateHeaders[0]
		}
	}

	// Determine event type based on body content
	var eventType events.EventType

	if strings.Contains(bodyLower, "malware") {
		// Extract malware name
		malwareName := common.FindStringWithoutMarkers(bodyLower, "malware known as", "")
		malwareName = strings.TrimSpace(strings.Trim(malwareName, " :"))
		eventType = events.NewMalware(malwareName)
	} else if strings.Contains(bodyLower, "phishing") {
		eventType = events.NewPhishing()
	} else if strings.Contains(bodyLower, "malicious activity") || strings.Contains(bodyLower, "imitating") {
		eventType = events.NewFraud()
	} else if strings.Contains(bodyLower, "compromised") {
		eventType = events.NewCompromisedAccount("")
	} else {
		return nil, &common.ParserError{Message: "could not find type string in report"}
	}

	// Create events
	var result []*events.Event

	if len(urls) == 0 {
		// No URLs, create single event with IP
		event := createEvent(ip, "", dateStr, eventType, incidentID)
		result = append(result, event)
	} else {
		// Create an event for each URL
		for _, url := range urls {
			cleanedURL := common.CleanURL(strings.TrimSpace(url))
			event := createEvent(ip, cleanedURL, dateStr, eventType, incidentID)
			result = append(result, event)
		}
	}

	if len(result) == 0 {
		return nil, &common.ParserError{Message: "no event created"}
	}

	return result, nil
}

func createEvent(ip, url, dateStr string, eventType events.EventType, incidentID string) *events.Event {
	event := events.NewEvent("cert_nz")
	event.IP = ip
	event.URL = url
	event.EventDate = email.ParseDate(dateStr)
	event.EventTypes = []events.EventType{eventType}

	// Add external ID if present
	if incidentID != "" {
		event.AddEventDetail(&events.ExternalID{ID: incidentID})
	}

	return event
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
