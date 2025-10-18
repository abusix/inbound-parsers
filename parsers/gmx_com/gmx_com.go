package gmx_com

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

var urlPattern = regexp.MustCompile(`(?i)(URL:)[^h.]*(?P<url>\S+)`)

// stripHTML removes HTML tags from a string (similar to BeautifulSoup text extraction)
func stripHTML(html string) string {
	// Remove script and style tags with their content
	scriptRe := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	html = scriptRe.ReplaceAllString(html, "")
	styleRe := regexp.MustCompile(`(?i)<style[^>]*>.*?</style>`)
	html = styleRe.ReplaceAllString(html, "")

	// Remove all HTML tags
	tagRe := regexp.MustCompile(`<[^>]+>`)
	html = tagRe.ReplaceAllString(html, " ")

	// Normalize whitespace
	wsRe := regexp.MustCompile(`\s+`)
	html = wsRe.ReplaceAllString(html, " ")

	return strings.TrimSpace(html)
}

// parseCompromisedWebsite parses compromised website reports
func (p *Parser) parseCompromisedWebsite(body string, dateFallback string) ([]*events.Event, error) {
	var result []*events.Event

	// Create event template
	eventTemplate := events.NewEvent("gmx_com")
	eventTemplate.EventTypes = []events.EventType{events.NewCompromisedWebsite("")}
	eventTemplate.EventDate = email.ParseDate(dateFallback)

	tag := "URLs:"
	if strings.Contains(body, tag) {
		// Replace tag to ensure newline after it
		bodyWithTag := strings.Replace(body, tag, tag+"\n", 1)
		urlBlock := common.GetBlockAfterWithStop(bodyWithTag, tag, "")

		for _, line := range urlBlock {
			event := events.NewEvent("gmx_com")
			event.EventTypes = []events.EventType{events.NewCompromisedWebsite("")}
			event.EventDate = eventTemplate.EventDate
			event.URL = line
			result = append(result, event)
		}
	} else {
		// Try to find URL using regex pattern
		if matches := urlPattern.FindStringSubmatch(body); len(matches) > 0 {
			// Get the named group 'url'
			for i, name := range urlPattern.SubexpNames() {
				if name == "url" && i < len(matches) {
					eventTemplate.URL = matches[i]
					result = append(result, eventTemplate)
					break
				}
			}
		}
	}

	return result, nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	// Strip HTML to get plain text (similar to BeautifulSoup)
	body = stripHTML(body)

	// Get date from headers
	dateFallback := ""
	if dateHeaders, exists := serializedEmail.Headers["date"]; exists && len(dateHeaders) > 0 {
		dateFallback = dateHeaders[0]
	}

	subjectLower := strings.ToLower(subject)
	if strings.Contains(subjectLower, "report abuse") {
		return p.parseCompromisedWebsite(body, dateFallback)
	}

	// If subject doesn't match expected pattern, return error
	return nil, &common.ParserError{Message: "Unknown subject type: " + subject}
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
