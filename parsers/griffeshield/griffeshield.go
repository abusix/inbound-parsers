// Package griffeshield implements the griffeshield.com parser
package griffeshield

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the griffeshield parser
type Parser struct{}

var (
	// Regex patterns for URL extraction
	immediateRemovalPattern = regexp.MustCompile(`(?i)please immediately make the (?P<url>http\S+) website not visible`)
	phishingSitePattern     = regexp.MustCompile(`(?i)site: (?P<url>.*)`)
	websiteIsPattern        = regexp.MustCompile(`(?i)website \S* is`)

	// Patterns for owner extraction (Go doesn't support lookbehind, so we capture the full match)
	behalfOfPattern    = regexp.MustCompile(`behalf of (.*) to`)
	perContoPattern    = regexp.MustCompile(`per conto di (.*) per`)
)

// cleanURL removes obfuscation characters from URLs
func cleanURL(url string) string {
	url = strings.ReplaceAll(url, ">", "")
	url = strings.ReplaceAll(url, " ", "")
	return url
}

// Parse parses emails from @griffeshield.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get body and subject
	bodyRaw, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Normalize line breaks in body (replace single \r\n with space, keep double)
	// Go doesn't support lookbehind, so we use a different approach
	// Replace \r\n\r\n with a placeholder, then replace remaining \r\n with space, then restore placeholder
	body := strings.ReplaceAll(bodyRaw, "\r\n\r\n", "<<<DOUBLE_NEWLINE>>>")
	body = strings.ReplaceAll(body, "\r\n", " ")
	body = strings.ReplaceAll(body, "<<<DOUBLE_NEWLINE>>>", "\r\n\r\n")

	// Extract trademark owner
	owner := ""
	if match := behalfOfPattern.FindStringSubmatch(body); len(match) > 1 {
		owner = match[1]
	} else if match := perContoPattern.FindStringSubmatch(body); len(match) > 1 {
		owner = match[1]
	}

	// Extract official URL
	officialURL := ""
	bodyLower := strings.ToLower(body)
	for _, marker := range []string{"sito ufficiale:", "official website:"} {
		if strings.Contains(bodyLower, marker) {
			officialURL = common.FindStringWithoutMarkers(bodyLower, marker, "")
			break
		}
	}

	// Get date fallback
	dateFallback := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateFallback = dateHeaders[0]
	}

	// Create event template
	createEventTemplate := func() *events.Event {
		event := events.NewEvent("griffeshield")
		event.EventDate = email.ParseDate(dateFallback)

		// Set Trademark event type with owner and official URL
		trademark := &events.Trademark{
			BaseEventType: events.BaseEventType{
				Name: "trademark",
				Type: "trademark",
			},
			TrademarkOwner: owner,
			OfficialURL:    officialURL,
		}
		event.EventTypes = []events.EventType{trademark}

		return event
	}

	var eventsSlice []*events.Event

	// Pattern 1: Check for immediate removal pattern
	if match := immediateRemovalPattern.FindStringSubmatch(body); len(match) > 0 {
		url := match[immediateRemovalPattern.SubexpIndex("url")]
		event := createEventTemplate()
		event.URL = url
		eventsSlice = append(eventsSlice, event)
		return eventsSlice, nil
	}

	// Pattern 2: Check for phishing site in subject
	if strings.Contains(strings.ToLower(subject), "phishing site:") {
		if match := phishingSitePattern.FindStringSubmatch(subject); len(match) > 0 {
			url := match[phishingSitePattern.SubexpIndex("url")]
			event := createEventTemplate()
			event.URL = url
			eventsSlice = append(eventsSlice, event)
			return eventsSlice, nil
		}
	}

	// Pattern 3: Check for various markers and extract URLs
	markers := []string{
		"following content",
		"link:",
		"WEBSITE",
		"website:",
		"web site:",
		"web sites:",
		"websites:",
		"following websites",
		"contents:",
		"links:",
		"very active online:",
		"active online at:",
		"violazione:",
		"il seguente sito internet:",
		"entro e non oltre 5 giorni:",
		"Link",
	}

	// Find which markers are present in body
	var foundMarkers []string
	for _, marker := range markers {
		if strings.Contains(body, marker) {
			foundMarkers = append(foundMarkers, marker)
		}
	}

	if len(foundMarkers) > 0 {
		for _, mark := range foundMarkers {
			// Insert double newline after marker for block extraction
			modifiedBody := strings.Replace(body, mark, mark+"\n\n", 1)
			urlAllBlock := common.GetBlockAfterWithStop(modifiedBody, mark, "")

			var urlBlock []string
			for _, el := range urlAllBlock {
				if strings.Contains(el, "<http:") {
					// Extract URL after <http:
					parts := strings.Split(el, "http")
					if len(parts) > 1 {
						urlBlock = append(urlBlock, "http"+cleanURL(parts[1]))
					}
				} else if strings.Contains(el, "http:") {
					// Extract all http: URLs
					parts := strings.Split(el, "http")
					for _, u := range parts {
						if u != "" {
							urlBlock = append(urlBlock, "http"+u)
						}
					}
				} else {
					// Use the block as-is
					urlBlock = urlAllBlock
				}
			}

			// Extract URLs from block
			found := false
			for _, url := range urlBlock {
				if strings.Contains(url, "http") || strings.Contains(url, "www") {
					event := createEventTemplate()
					event.URL = url
					eventsSlice = append(eventsSlice, event)
					found = true
				}
			}

			if found {
				break
			}
		}

		if len(eventsSlice) > 0 {
			return eventsSlice, nil
		}
	}

	// Pattern 4: Check for "website <url> is" pattern
	if match := websiteIsPattern.FindStringSubmatch(strings.ToLower(body)); len(match) > 0 {
		url := match[0]
		event := createEventTemplate()
		event.URL = url
		eventsSlice = append(eventsSlice, event)
		return eventsSlice, nil
	}

	// If no patterns matched, return error
	return nil, common.NewParserError("infringing url not found adapt the parser")
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
