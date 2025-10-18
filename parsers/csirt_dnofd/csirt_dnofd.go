package csirt_dnofd

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	ipPattern = regexp.MustCompile(`\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}`)
)

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)

	// Get date fallback
	dateFallback := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateFallback = dateHeaders[0]
	}

	if strings.Contains(subjectLower, "phishing") {
		return parsePhishing(body, subject, dateFallback)
	}

	return nil, common.NewNewTypeError(subject)
}

// parseDateTime attempts to parse various datetime formats used by csirt_dnofd
func parseDateTime(dateStr string) *time.Time {
	dateStr = strings.TrimSpace(dateStr)
	if dateStr == "" {
		return nil
	}

	// Try ISO 8601 format with microseconds first (format used in body)
	formats := []string{
		time.RFC3339Nano,              // "2006-01-02T15:04:05.999999999Z07:00"
		time.RFC3339,                  // "2006-01-02T15:04:05Z07:00"
		"2006-01-02T15:04:05.999999999-07:00", // With microseconds
		"2006-01-02T15:04:05-07:00",   // Without microseconds
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return &t
		}
	}

	// Fallback to email.ParseDate for header dates
	return email.ParseDate(dateStr)
}

func parsePhishing(body, subject, dateFallback string) ([]*events.Event, error) {
	event := events.NewEvent("csirt_dnofd")

	// Extract event date
	if date := common.FindStringWithoutMarkers(body, "phishing web site at", "hosted"); date != "" {
		date = strings.TrimSpace(date)
		eventDate := parseDateTime(date)
		event.EventDate = eventDate
	} else {
		eventDate := parseDateTime(dateFallback)
		event.EventDate = eventDate
	}

	// Extract IP from subject
	if ipMatch := ipPattern.FindString(subject); ipMatch != "" {
		cleanIP := strings.ReplaceAll(ipMatch, "[", "")
		cleanIP = strings.ReplaceAll(cleanIP, "]", "")
		// Validate it's a proper IP
		if validIP := common.IsIP(cleanIP); validIP != "" {
			event.IP = validIP
		}
	}

	// Extract phishing URL
	urlBlock := common.GetBlockAfterWithStop(body, "hosted at:", "")
	phishingURL := getURL(urlBlock)
	if phishingURL != "" {
		event.URL = phishingURL
	}

	// Extract official URL
	officialBlock := common.GetBlockAfterWithStop(body, "legitimate website is:", "")
	officialURL := getURL(officialBlock)

	// Only create event if we have IP or URL
	if event.IP != "" || event.URL != "" {
		var phishingEvent *events.Phishing
		if officialURL != "" {
			phishingEvent = events.NewPhishingWithOfficialURL(officialURL)
		} else {
			phishingEvent = events.NewPhishing()
		}
		event.EventTypes = []events.EventType{phishingEvent}
		return []*events.Event{event}, nil
	}

	return nil, common.NewParserError("no IP or URL found in phishing report")
}

func getURL(urlBlock []string) string {
	for _, line := range urlBlock {
		eligibleURL := common.CleanURL(line)
		eligibleURL = strings.ReplaceAll(eligibleURL, "*", "")
		if common.IsURL(eligibleURL) {
			return eligibleURL
		}
	}
	return ""
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
