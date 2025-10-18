package latam

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

// stripHTML removes HTML tags from a string (mimics BeautifulSoup's text extraction)
func stripHTML(html string) string {
	// Remove all HTML tags
	re := regexp.MustCompile(`<[^>]*>`)
	text := re.ReplaceAllString(html, "")
	return text
}

// parsePhishing handles phishing reports from LATAM
func parsePhishing(body string, event *events.Event, dateFallback string) ([]*events.Event, error) {
	// Set event date from fallback
	if dateFallback != "" {
		event.EventDate = email.ParseDate(dateFallback)
	}

	// Extract official URL
	officialURL := strings.TrimSpace(common.FindStringWithoutMarkers(body, "legitimate website is:", ""))

	// Create phishing event type
	event.EventTypes = []events.EventType{
		events.NewPhishingWithOfficialURL(officialURL),
	}

	// Extract phishing URL
	url := common.GetNonEmptyLineAfter(body, "phishing website hosted at:")
	url = strings.ReplaceAll(url, " ", "")
	event.URL = url

	// Extract IP address
	ip := common.FindStringWithoutMarkers(body, "IP:", "")
	ip = strings.ReplaceAll(ip, " ", "")
	ip = strings.ReplaceAll(ip, "[.]", ".")
	event.IP = ip

	return []*events.Event{event}, nil
}

// parseTrademark handles trademark/content removal reports from LATAM
func parseTrademark(body string, event *events.Event, dateFallback string) ([]*events.Event, error) {
	// Set event date from fallback
	if dateFallback != "" {
		event.EventDate = email.ParseDate(dateFallback)
	}

	// Extract official URL
	officialURL := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Official Website:", ""))

	// Extract registration number
	regNum := common.FindStringWithoutMarkers(body, "registration number", "")
	regNum = strings.TrimSuffix(strings.TrimSpace(regNum), ".")

	// Create trademark event type
	registrationNumbers := []string{}
	if regNum != "" {
		registrationNumbers = append(registrationNumbers, regNum)
	}

	event.EventTypes = []events.EventType{
		&events.Trademark{
			BaseEventType: events.BaseEventType{
				Name: "trademark",
				Type: "trademark",
			},
			OfficialURL:         officialURL,
			RegistrationNumbers: registrationNumbers,
		},
	}

	// Extract URL from ATTACHMENT line
	url := common.GetNonEmptyLineAfter(body, "ATTACHMENT:")
	event.URL = url

	return []*events.Event{event}, nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	event := events.NewEvent("latam")

	// Get email body
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Get subject
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Strip HTML tags from body to get plain text (mimics BeautifulSoup)
	parsedBody := stripHTML(body)

	// Extract external ID from subject if present
	extID := common.FindStringWithoutMarkers(subject, "(Tracking:", ")")
	if extID != "" {
		event.AddEventDetail(&events.ExternalID{ID: strings.TrimSpace(extID)})
	}

	// Get date from headers for fallback
	dateFallback := ""
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		dateFallback = dateHeader[0]
	}

	// Route to appropriate parser based on subject
	if strings.Contains(subject, "Phishing") {
		return parsePhishing(parsedBody, event, dateFallback)
	}

	if strings.Contains(subject, "Content Removal") || strings.Contains(subject, "Fake Profile") {
		return parseTrademark(parsedBody, event, dateFallback)
	}

	// Unknown subject type
	return nil, common.NewParserError("unknown subject type: " + subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
