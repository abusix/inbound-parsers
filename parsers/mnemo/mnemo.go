package mnemo

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get email date
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Strip HTML tags from body
	bodyText := stripHTML(body)
	bodyLower := strings.ToLower(bodyText)

	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	var evts []*events.Event

	if strings.Contains(subjectLower, "phishing") {
		// Parse phishing report
		originalURL := common.FindStringWithoutMarkers(bodyText, "The REAL WEBSITE of our client is:", "Evidence")

		// Try first pattern
		url := common.FindStringWithoutMarkers(bodyText, "URL PHISHING: ", "The REAL WEBSITE")
		if url == "" {
			// Try second pattern
			url = common.FindStringWithoutMarkers(bodyText, "Evidence:", "The fraudulent website")
		}

		if url != "" {
			// Clean up obfuscation
			url = strings.ReplaceAll(url, "[:]", ":")
			url = strings.ReplaceAll(url, "[//]", "//")

			event := events.NewEvent("mnemo")
			event.EventDate = eventDate
			event.URL = url
			event.EventTypes = []events.EventType{events.NewPhishingWithOfficialURL(originalURL)}
			evts = append(evts, event)
		}
	} else if strings.Contains(bodyLower, "abuso de marca") {
		// Parse trademark report
		url := common.FindStringWithoutMarkers(bodyText, "contenido no autorizado:", "Evidencia:")
		if url != "" {
			// Clean up obfuscation
			url = strings.ReplaceAll(url, "[://]", "://")

			event := events.NewEvent("mnemo")
			event.EventDate = eventDate
			event.URL = url
			event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}
			evts = append(evts, event)
		}
	} else {
		return nil, common.NewNewTypeError(subjectLower)
	}

	return evts, nil
}

// stripHTML removes HTML tags from a string
func stripHTML(html string) string {
	// Replace br/div/span tags with newlines
	html = regexp.MustCompile(`(?i)<br[^>]*>`).ReplaceAllString(html, "\n")
	html = regexp.MustCompile(`(?i)<div[^>]*>`).ReplaceAllString(html, "\n")
	html = regexp.MustCompile(`(?i)<span[^>]*>`).ReplaceAllString(html, "\n")

	// Remove all other HTML tags
	html = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(html, "")

	return html
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
