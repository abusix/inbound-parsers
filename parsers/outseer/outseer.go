package outseer

import (
	"strings"

	"github.com/PuerkitoBio/goquery"
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

	// Get email body
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		// Try to get body from HTML attachment
		body, err = common.FindFirstAttachmentWithMimeType(serializedEmail, "html")
		if err != nil {
			return nil, err
		}
	}

	// Create base event
	event := events.NewEvent("outseer")

	// Set event date
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	// Parse HTML body
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	bodyText := doc.Text()
	bodyLower := strings.ToLower(body)

	// Check if this is a valid report type
	if !containsAny(subjectLower, []string{"malicious", "phish", "fraud"}) &&
		!containsAny(bodyLower, []string{"malware", "phish", "fraud"}) {
		return nil, common.NewNewTypeError(subject)
	}

	// Get URL
	url := getURL(doc, bodyText)

	// Get IP
	ip := strings.ReplaceAll(common.FindStringWithoutMarkers(bodyText, "IP:", "\n"), " ", "")

	// Set event data if we have IP or URL
	if ip == "" && url == "" {
		return nil, nil
	}

	event.IP = ip
	event.URL = url

	// Determine event type
	if strings.Contains(subjectLower, "phis") ||
		strings.Contains(bodyText, "phishing") ||
		strings.Contains(bodyText, "robo de identidad") {
		phishing := events.NewPhishing()
		phishing.OfficialURL = url
		event.EventTypes = []events.EventType{phishing}
	} else if strings.Contains(subjectLower, "malicious") || strings.Contains(bodyText, "malware") {
		malwareName := common.FindStringWithoutMarkers(bodyText, "Malware name:", "\n")
		malwareName = strings.Split(malwareName, "(see description below)")[0]
		malwareName = strings.TrimSpace(malwareName)
		event.EventTypes = []events.EventType{events.NewMalware(malwareName)}
	} else {
		event.EventTypes = []events.EventType{events.NewFraud()}
	}

	return []*events.Event{event}, nil
}

// getURL extracts URL from the email body using multiple strategies
func getURL(doc *goquery.Document, bodyText string) string {
	protocols := []string{"hxxp", "hxxps", "http", "https"}

	// Strategy 1: Look for URLs in <b> tags
	var eligibleURLs []string
	doc.Find("b").Each(func(i int, s *goquery.Selection) {
		text := s.Text()
		if text != "" && containsAny(text, protocols) {
			eligibleURLs = append(eligibleURLs, text)
		}
	})

	if len(eligibleURLs) > 0 {
		return common.CleanURL(eligibleURLs[0])
	}

	// Strategy 2: Find URL between "URL:" and "IP:" markers
	if url := common.CleanURL(common.FindStringWithoutMarkers(bodyText, "URL:", "IP:")); url != "" {
		return url
	}

	// Strategy 3: Look for URLs in <a> tags
	eligibleURLs = nil
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		text := s.Text()
		if text != "" && !strings.Contains(text, "@") {
			// Add http:// prefix if no protocol is present
			if !containsAny(text, protocols) {
				text = "http://" + text
			}
			eligibleURLs = append(eligibleURLs, text)
		}
	})

	if len(eligibleURLs) > 0 {
		return common.CleanURL(eligibleURLs[0])
	}

	return ""
}

// containsAny checks if a string contains any of the given substrings
func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
