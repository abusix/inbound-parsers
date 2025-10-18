// Package promusicae implements the Promusicae parser for copyright infringement reports
package promusicae

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

var urlPattern = regexp.MustCompile(`(?i)(?P<url>http\S+)`)

// Parser implements the Promusicae parser
type Parser struct{}

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

// parseCopyright parses copyright infringement reports
func (p *Parser) parseCopyright(body string, eventTemplate *events.Event, dateFallback *time.Time) ([]*events.Event, error) {
	var result []*events.Event

	// Set event date from fallback
	eventTemplate.EventDate = dateFallback

	// Set event type
	eventTemplate.EventTypes = []events.EventType{&events.Copyright{}}

	// Extract external ID
	externalID := strings.TrimSpace(common.FindStringWithoutMarkers(body, "REF:", "\n"))
	if externalID != "" {
		eventTemplate.AddEventDetail(&events.ExternalID{ID: externalID})
	}

	// Add copyright owner organization
	address := ""
	addressCandidate := "C/ María de Molina, nº 39, 6ª 28006, Madrid (Spain)"
	if strings.Contains(strings.ToLower(body), strings.ToLower(addressCandidate)) {
		address = "C/ Maria de Molina, N 39, 6 28006, Madrid (Spain)"
	}

	owner := &events.Organisation{
		Name:         "copyright_owner",
		Address:      address,
		ContactEmail: "antipirateria@promusicae.es",
	}
	eventTemplate.AddEventDetail(owner)

	// Find URLs in the body after the tag
	tag := "productores de música de españa – promusicae"
	lowerBody := strings.ToLower(body)
	lowerBody = strings.ReplaceAll(lowerBody, tag, tag+"\n")
	urlBlock := common.GetBlockAfterWithStop(lowerBody, tag, "")

	for _, line := range urlBlock {
		matches := urlPattern.FindStringSubmatch(line)
		if len(matches) > 0 {
			// Create a copy of the event template
			event := events.NewEvent(eventTemplate.Parser)
			event.EventDate = eventTemplate.EventDate
			event.EventTypes = eventTemplate.EventTypes
			event.EventDetails = eventTemplate.EventDetails
			event.URL = matches[0]
			result = append(result, event)
		}
	}

	return result, nil
}

// Parse parses emails from @promusicae.es
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Strip HTML to get plain text
	body = stripHTML(body)

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Check for copyright notice
	if strings.Contains(strings.ToLower(subject), "notice of infringement") &&
		strings.Contains(strings.ToLower(body), "copyright") {

		// Get date fallback
		var dateFallback *time.Time
		if serializedEmail.Headers != nil {
			if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
				dateFallback = email.ParseDate(dateHeaders[0])
			}
		}

		eventTemplate := events.NewEvent("promusicae")
		return p.parseCopyright(body, eventTemplate, dateFallback)
	}

	return nil, common.NewNewTypeError(subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
