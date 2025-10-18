// Package magazineluiza implements the Magazine Luiza parser
package magazineluiza

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the magazineluiza parser
type Parser struct{}

// NewParser creates a new Parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from Magazine Luiza (takedown.efc@magazineluiza.com.br)
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get body and strip HTML
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	body = stripHTML(body)

	// Get subject
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	// Get event date from headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	// Extract external ID from subject: (Tracking: XXX)
	externalID := common.FindStringWithoutMarkers(subject, "(Tracking:", ")")
	externalID = strings.TrimSpace(externalID)

	// Create event template
	eventTemplate := events.NewEvent("magazineluiza")
	eventTemplate.EventDate = eventDate
	if externalID != "" {
		eventTemplate.AddEventDetail(&events.ExternalID{ID: externalID})
	}

	// Check for XLSX attachment - return early with TODO error if found
	// The Python version uses get_xlsx_attachment_as_csv which is not yet implemented in Go
	if hasXLSXAttachment(serializedEmail) {
		return nil, common.NewParserError("XLSX attachment parsing not yet implemented for magazineluiza")
	}

	// Route based on subject
	if strings.Contains(subjectLower, "content removal") {
		return parseTrademark(body, eventTemplate)
	} else if strings.Contains(subjectLower, "phishing hosted at your site") {
		return parsePhishing(body, eventTemplate)
	}

	return nil, common.NewNewTypeError("Unknown magazineluiza email type: " + subject)
}

// parseTrademark handles trademark/content removal reports
func parseTrademark(body string, eventTemplate *events.Event) ([]*events.Event, error) {
	// Extract official URL
	officialURL := common.FindStringWithoutMarkers(body, "Official website: ", "\n")
	officialURL = strings.TrimSpace(officialURL)

	// Extract trademark numbers (comma-separated list)
	trademarkNumbersStr := common.FindStringWithoutMarkers(body, "under the numbers ", " and the")
	var trademarkNumbers []string
	if trademarkNumbersStr != "" {
		for _, num := range strings.Split(trademarkNumbersStr, ",") {
			trademarkNumbers = append(trademarkNumbers, strings.TrimSpace(num))
		}
	}

	// Extract trademarked material
	trademarkedMaterial := common.FindStringWithoutMarkers(body, "The trademark", "is registered with the")
	trademarkedMaterial = strings.TrimSpace(trademarkedMaterial)

	// Create trademark event type
	trademark := events.NewTrademark("", trademarkNumbers, "", trademarkedMaterial)
	trademark.OfficialURL = officialURL
	eventTemplate.EventTypes = []events.EventType{trademark}

	// Extract URL from ATTACHMENT: section
	eventTemplate.URL = common.GetNonEmptyLineAfter(body, "ATTACHMENT:")

	return []*events.Event{eventTemplate}, nil
}

// parsePhishing handles phishing reports
func parsePhishing(body string, eventTemplate *events.Event) ([]*events.Event, error) {
	// Extract official URL
	officialURL := common.FindStringWithoutMarkers(body, "legitimate website is: ", "\n")
	officialURL = strings.TrimSpace(officialURL)

	// Create phishing event type
	eventTemplate.EventTypes = []events.EventType{events.NewPhishingWithOfficialURL(officialURL)}

	// Extract phishing URL
	eventTemplate.URL = common.GetNonEmptyLineAfter(body, "We detected a phishing website hosted at:")

	// Extract IP
	eventTemplate.IP = common.FindStringWithoutMarkers(body, "IP:", "")

	return []*events.Event{eventTemplate}, nil
}

// parseXLSX handles XLSX attachments (not yet implemented)
// This would be called if XLSX support is added
func parseXLSX(body, subjectLower, rawCSV string, eventTemplate *events.Event) ([]*events.Event, error) {
	var results []*events.Event

	// Determine event type based on subject
	if strings.Contains(subjectLower, "phishing sites hosted on your network") {
		officialURL := common.FindStringWithoutMarkers(body, "legitimate website is:", "\n")
		officialURL = strings.TrimSpace(officialURL)
		eventTemplate.EventTypes = []events.EventType{events.NewPhishingWithOfficialURL(officialURL)}
	} else {
		return nil, common.NewNewTypeError("Unknown XLSX type: " + subjectLower)
	}

	// Extract URLs from CSV content
	urlPattern := regexp.MustCompile(`(?P<url>http\S+)`)
	for _, line := range strings.Split(rawCSV, "\n") {
		if matches := urlPattern.FindStringSubmatch(line); len(matches) > 0 {
			// Create a copy of the event template
			event := events.NewEvent(eventTemplate.Parser)
			event.EventDate = eventTemplate.EventDate
			event.EventDetails = append([]events.EventDetail{}, eventTemplate.EventDetails...)
			event.EventTypes = []events.EventType{eventTemplate.EventTypes[0]}
			event.URL = matches[0]
			results = append(results, event)
		}
	}

	return results, nil
}

// hasXLSXAttachment checks if the email has an XLSX attachment
func hasXLSXAttachment(serializedEmail *email.SerializedEmail) bool {
	for _, part := range serializedEmail.Parts {
		if part.Headers != nil {
			if disposition, ok := part.Headers["content-disposition"]; ok {
				for _, disp := range disposition {
					if strings.Contains(strings.ToLower(disp), "xlsx") {
						return true
					}
				}
			}
			if contentType, ok := part.Headers["content-type"]; ok {
				for _, ct := range contentType {
					if strings.Contains(strings.ToLower(ct), "xlsx") ||
						strings.Contains(strings.ToLower(ct), "spreadsheetml") {
						return true
					}
				}
			}
		}
	}
	return false
}

// stripHTML removes HTML tags from a string
// This is a simple implementation similar to BeautifulSoup(body, 'lxml').text
func stripHTML(s string) string {
	// Remove script and style tags with their content
	scriptRe := regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	s = scriptRe.ReplaceAllString(s, "")
	styleRe := regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	s = styleRe.ReplaceAllString(s, "")

	// Remove all HTML tags
	tagRe := regexp.MustCompile(`<[^>]+>`)
	s = tagRe.ReplaceAllString(s, " ")

	// Decode common HTML entities
	s = strings.ReplaceAll(s, "&nbsp;", " ")
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&quot;", "\"")
	s = strings.ReplaceAll(s, "&#39;", "'")
	s = strings.ReplaceAll(s, "&apos;", "'")

	// Clean up whitespace
	s = regexp.MustCompile(`\s+`).ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
