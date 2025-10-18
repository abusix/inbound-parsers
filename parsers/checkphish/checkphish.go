package checkphish

import (
	"fmt"
	"regexp"
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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, _ := common.GetSubject(serializedEmail, false)

	// Check for trademark reports
	if strings.Contains(strings.ToLower(subject), "trademark") || strings.Contains(body, "trademark") {
		return parseTrademark(serializedEmail, body)
	}

	// Check for fraud reports
	if strings.Contains(body, "fraudulent activity") || strings.Contains(body, "scam") {
		return parseFraud(serializedEmail, body)
	}

	// Try HTML parsing first
	event := events.NewEvent("checkphish")
	url := ""
	details := ""
	brand := ""
	ip := ""

	// Set event date
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	// Try to parse HTML body
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err == nil {
		// Try to find the table structure matching Python's BeautifulSoup path
		table := doc.Find("table.main")
		if table.Length() > 0 {
			data := table.Find("tr").First().Find("td").First().Find("table").Find("tr").First().Find("td")
			paragraphs := data.Find("p")

			if paragraphs.Length() >= 3 {
				// Extract phish data from second paragraph (index 1)
				phishText := paragraphs.Eq(1).Text()
				parts := strings.Fields(phishText)
				if len(parts) > 0 {
					url = strings.ReplaceAll(parts[0], "[.]", ".")
				}
				if paragraphs.Eq(1).Find("string").Length() > 0 {
					brand = paragraphs.Eq(1).Find("string").Text()
				}

				// Extract details URL from third paragraph (index 2)
				if link := paragraphs.Eq(2).Find("a"); link.Length() > 0 {
					details, _ = link.Attr("href")
				}
			}
		}
	}

	// Fallback parsing methods if HTML parsing failed
	if url == "" {
		if strings.Contains(body, "Hi there") {
			line := common.GetNonEmptyLineAfter(body, "Hi there")
			parts := strings.SplitN(line, " ", 2)
			if len(parts) > 0 {
				url = common.CleanURL(parts[0])
			}
			if len(parts) > 1 {
				brand = common.FindStringWithoutMarkers(parts[1], "*", "*")
			}
			details = strings.Trim(common.GetNonEmptyLineAfter(body, "See complete details here"), "<>")
		} else if strings.Contains(body, "fraudulent") {
			url = common.GetNonEmptyLineAfter(body, "URL:")
			url = common.CleanURL(url)
			brand = common.FindStringWithoutMarkers(body, "targeting", "customers")
			ip = common.FindStringWithoutMarkers(body, "IP address for this site is:", "")
		}
	}

	// Check if this is a phishing event
	if strings.Contains(body, "phish") && strings.Contains(body, "hosting") {
		phishing := events.NewPhishing()
		phishing.PhishingTarget = url
		event.EventTypes = []events.EventType{phishing}
	} else {
		// Fall back to simple format parsing
		return parseSimpleFormat(serializedEmail, strings.ToLower(body))
	}

	event.IP = ip
	event.URL = url

	// Add event details
	if details != "" {
		event.AddEventDetail(&events.Organisation{
			Name:        "reporter",
			URLOrDomain: details,
		})
	}

	if brand != "" {
		event.AddEventDetail(&events.Target{
			Brand: brand,
		})
	}

	return []*events.Event{event}, nil
}

func parseTrademark(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	body = strings.ReplaceAll(body, "hxxp", "http")

	event := events.NewEvent("checkphish")

	// Set event date
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	// Extract URL
	urlPart := common.FindStringWithoutMarkers(body, "http", "")
	url := "http" + strings.ReplaceAll(urlPart, "[.]", ".")

	// Extract IP
	ip := common.FindStringWithoutMarkers(body, "The IP", "")

	// Extract registration numbers
	regNumStr := common.FindStringWithoutMarkers(body, "Registration Numbers:", "")
	regNumRegex := regexp.MustCompile(`\d+`)
	registrationNumbers := regNumRegex.FindAllString(regNumStr, -1)

	// Extract trademark owner
	trademarkOwner := common.FindStringWithoutMarkers(body, "The site is made to look like the actual", "site")

	event.URL = url
	event.IP = ip

	trademark := events.NewTrademark("", registrationNumbers, trademarkOwner, "")
	event.EventTypes = []events.EventType{trademark}

	return []*events.Event{event}, nil
}

func parseFraud(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	var eventsResult []*events.Event

	// Get all URLs in the block after "following URL"
	urls := common.GetBlockAfterWithStop(body, "following URL", "")

	for _, urlLine := range urls {
		event := events.NewEvent("checkphish")

		// Clean the URL
		url := strings.ReplaceAll(urlLine, "hxxp", "http")
		url = strings.ReplaceAll(url, "[", "")
		url = strings.ReplaceAll(url, "]", "")

		event.URL = url

		// Set event date
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
				event.EventDate = parsedDate
			}
		}

		event.EventTypes = []events.EventType{events.NewFraud()}
		eventsResult = append(eventsResult, event)
	}

	return eventsResult, nil
}

func parseSimpleFormat(serializedEmail *email.SerializedEmail, bodyLower string) ([]*events.Event, error) {
	var eventsResult []*events.Event

	ip := common.ExtractOneIP(bodyLower)

	// Find all URLs containing hxxp
	var urls []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(bodyLower, "\n") {
		if strings.Contains(line, "hxxp") {
			cleanedURL := common.CleanURL(line)
			if !seen[cleanedURL] {
				urls = append(urls, cleanedURL)
				seen[cleanedURL] = true
			}
		}
	}

	if len(urls) == 0 {
		return nil, &common.ParserError{Message: "no event created"}
	}

	for _, urlLine := range urls {
		event := events.NewEvent("checkphish")

		// Set event date
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
				event.EventDate = parsedDate
			}
		}

		event.IP = ip

		// Extract URL - get everything after "http"
		parts := strings.Split(urlLine, "http")
		if len(parts) > 1 {
			event.URL = "http" + parts[1]
		}

		// Determine event type
		if strings.Contains(bodyLower, "phishing") {
			phishing := events.NewPhishing()
			phishing.PhishingTarget = urlLine
			event.EventTypes = []events.EventType{phishing}
		} else if strings.Contains(bodyLower, "scam") || strings.Contains(bodyLower, "fraud") {
			event.EventTypes = []events.EventType{events.NewFraud()}
		} else {
			// NewTypeError - in Go we'll just use a generic type or return an error
			// For now, let's default to fraud
			if subject, ok := serializedEmail.Headers["subject"]; ok && len(subject) > 0 {
				return nil, fmt.Errorf("new type error: %s", subject[0])
			}
			event.EventTypes = []events.EventType{events.NewFraud()}
		}

		eventsResult = append(eventsResult, event)
	}

	return eventsResult, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
