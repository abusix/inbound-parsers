package ncmec

import (
	"encoding/base64"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var ipPattern = regexp.MustCompile(`\d{0,3}\.\d{0,3}\.\d{0,3}\.\d{0,3}`)

func NewParser() *Parser {
	return &Parser{}
}

// parseNormalStyle handles the "Notice of possible child exploitation on your service" format
func parseNormalStyle(body string, eventDate string) ([]*events.Event, error) {
	var eventList []*events.Event
	urlsMap := make(map[string]bool)

	// Get URLs using GetContinuousLinesUntilEmptyLine
	lines := common.GetContinuousLinesUntilEmptyLine(body, "received a number of reports for the same domain")
	for _, line := range lines {
		url := common.CleanURL(line)
		urlsMap[url] = true
	}

	// Extract IP
	var ip string
	ipMatch := ipPattern.FindString(body)
	if ipMatch != "" {
		ip = common.IsIP(ipMatch)
	}

	// Parse the date
	var parsedDate *time.Time
	if eventDate != "" {
		parsedDate = email.ParseDate(eventDate)
	}

	// Create events for each URL
	for url := range urlsMap {
		event := events.NewEvent("ncmec")
		event.EventTypes = []events.EventType{events.NewChildAbuse()}

		url = common.CleanURL(url)
		url = strings.Trim(url, "* ")

		if ip != "" {
			event.IP = ip
		}
		event.URL = url

		if parsedDate != nil {
			event.EventDate = parsedDate
		}

		eventList = append(eventList, event)
	}

	return eventList, nil
}

// extractHTMLURLs extracts URLs from HTML body using goquery
func extractHTMLURLs(body string) []string {
	var urls []string

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return urls
	}

	// Extract text nodes
	doc.Find("*").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		if strings.HasPrefix(text, "http") {
			urls = append(urls, text)
		}
	})

	return urls
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	var eventList []*events.Event

	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, &common.ParserError{Message: "body not found"}
	}

	// Check for base64 encoding
	if serializedEmail.Headers != nil {
		if cte, ok := serializedEmail.Headers["content-transfer-encoding"]; ok {
			if len(cte) > 0 && strings.Contains(strings.ToLower(cte[0]), "base64") {
				decoded, err := base64.StdEncoding.DecodeString(body)
				if err == nil {
					body = string(decoded)
				}
			}
		}
	}

	// Get date from headers
	var dateStr string
	var parsedDate *time.Time
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			dateStr = dateHeaders[0]
			parsedDate = email.ParseDate(dateStr)
		}
	}

	// Check subject to determine parsing style
	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	if strings.Contains(subjectLower, "notice of possible child exploitation on your service") {
		return parseNormalStyle(body, dateStr)
	}

	// Alternative format
	eventTemplate := events.NewEvent("ncmec")
	eventTemplate.EventTypes = []events.EventType{events.NewChildAbuse()}
	if parsedDate != nil {
		eventTemplate.EventDate = parsedDate
	}

	urlsMap := make(map[string]bool)
	ipFound := false

	// Extract URLs from HTML
	htmlURLs := extractHTMLURLs(body)
	urlsExtracted := len(htmlURLs) > 0
	for _, url := range htmlURLs {
		urlsMap[url] = true
	}

	// Parse body line by line
	for _, line := range strings.Split(body, "\n") {
		// Extract IP
		ipMatch := ipPattern.FindString(line)
		if ipMatch != "" && !ipFound {
			ip := common.ExtractOneIP(line)
			ip = common.IsIP(ip)
			if ip != "" {
				ipFound = true
				eventTemplate.IP = ip
			}
		}

		// Extract URLs from lines
		trimmed := strings.Trim(line, "* ")
		if strings.HasPrefix(trimmed, "http") && !urlsExtracted {
			urlsMap[line] = true
		}
	}

	// No protocol specified - extract domain after specific token
	if len(urlsMap) == 0 {
		token := "reports for the same domain. \n\n"
		startIdx := strings.Index(body, token)
		if startIdx >= 0 {
			startIdx += len(token)
			remaining := body[startIdx:]
			endIdx := strings.Index(remaining, "\n")
			if endIdx >= 0 {
				url := remaining[:endIdx]
				urlsMap[url] = true
			} else {
				urlsMap[remaining] = true
			}
		}
	}

	// Create events for each URL
	for url := range urlsMap {
		event := events.NewEvent("ncmec")
		event.EventTypes = eventTemplate.EventTypes
		event.IP = eventTemplate.IP
		event.EventDate = eventTemplate.EventDate

		url = strings.Trim(url, "* ")
		event.URL = url

		eventList = append(eventList, event)
	}

	if len(eventList) == 0 {
		return nil, &common.ParserError{Message: "no in ncmec parser events created"}
	}

	return eventList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
