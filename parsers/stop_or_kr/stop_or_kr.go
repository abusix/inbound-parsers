// Package stop_or_kr implements the stop.or.kr parser for sexual abuse reports
package stop_or_kr

import (
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the stop.or.kr parser
type Parser struct{}

// NewParser creates a new Parser instance
func NewParser() *Parser {
	return &Parser{}
}

// getURLs extracts URLs from HTML body, excluding reporter URLs
func getURLs(doc *goquery.Document) []string {
	// Reporter URLs to exclude
	excludeURLs := []string{
		"https://www.facebook.com/wmhotline2",
		"https://twitter.com/whrik200",
		"https://www.women1366.kr/",
		"http://blog.naver.com/whrck",
	}

	var urls []string
	seen := make(map[string]bool)

	// Extract all text and find lines with URLs
	doc.Find("*").Each(func(i int, s *goquery.Selection) {
		text := s.Text()
		lines := strings.Split(text, "\n")

		for _, line := range lines {
			// Remove everything before "http"
			re := regexp.MustCompile(`(.*?)(http)`)
			line = re.ReplaceAllString(line, "")
			line = strings.TrimSpace(line)

			// Check if line starts with http
			if !strings.HasPrefix(line, "http") {
				continue
			}

			// Remove = characters for comparison
			lineClean := strings.ReplaceAll(line, "=", "")

			// Exclude reporter URLs
			isExcluded := false
			for _, excludeURL := range excludeURLs {
				excludeClean := strings.ReplaceAll(excludeURL, "=", "")
				if strings.Contains(lineClean, excludeClean) || strings.Contains(excludeClean, lineClean) {
					isExcluded = true
					break
				}
			}

			if !isExcluded && !seen[line] {
				urls = append(urls, line)
				seen[line] = true
			}
		}
	})

	return urls
}

// Parse parses emails from stop.or.kr
// These emails report sexual abuse / non-consensual sexually explicit material
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	var body string

	// Try to get raw HTML body first (from parts[1].body_raw)
	// since normal body does not contain dots in URLs for some reason
	if len(serializedEmail.Parts) > 1 {
		part := serializedEmail.Parts[1]
		switch b := part.Body.(type) {
		case string:
			body = b
		case []byte:
			body = string(b)
		}
	}

	// Fallback to normal body if no HTML found
	if body == "" {
		var err error
		body, err = common.GetBody(serializedEmail, false)
		if err != nil || body == "" {
			return nil, common.NewParserError("empty email body")
		}
		body = strings.ToLower(body)
	}

	// Parse HTML body
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return nil, common.NewParserError("failed to parse HTML: " + err.Error())
	}

	// Extract URLs
	urls := getURLs(doc)
	if len(urls) == 0 {
		return nil, common.NewParserError("no url found")
	}

	// Get event date from email headers
	var eventDate string
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = dateHeaders[0]
	}

	// Create one event per URL
	var eventsList []*events.Event
	for _, url := range urls {
		event := events.NewEvent("stop_or_kr")

		// Set event date
		if eventDate != "" {
			event.EventDate = email.ParseDate(eventDate)
		}

		// Set URL
		event.URL = url

		// Set event type
		// Not always ChildAbuse but we don't have a better type
		// for sexual abuse / non-consensual sexually explicit material
		event.EventTypes = []events.EventType{events.NewChildAbuse()}

		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
