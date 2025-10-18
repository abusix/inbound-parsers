package viaccessorca

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// datePattern matches dates like "2022/09/01 12:18:34 UTC"
var datePattern = regexp.MustCompile(`(?P<year>\d{4})/(?P<month>\d{2})/(?P<day>\d{2})\s(?P<time>\d\d:\d\d:\d\d)`)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)

	if strings.Contains(subjectLower, "notice of infringement") {
		// Get the date fallback from headers
		var dateFallback *time.Time
		if serializedEmail.Headers != nil {
			if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
				dateFallback = parseEmailDate(dateHeaders[0])
			}
		}

		return parseCopyright(body, subject, dateFallback)
	}

	return nil, fmt.Errorf("unknown email type: %s", subject)
}

func parseCopyright(body, subject string, dateFallback *time.Time) ([]*events.Event, error) {
	eventTemplate := events.NewEvent("viaccessorca")
	eventTemplate.IP = subject

	// Parse event date from body
	bodySplit := strings.Split(body, "\n")
	foundDate := false
	for _, line := range bodySplit {
		if datePattern.MatchString(line) {
			if parsedDate := parseDateFromLine(line); parsedDate != nil {
				eventTemplate.EventDate = parsedDate
				foundDate = true
				break
			}
		}
	}

	if !foundDate && dateFallback != nil {
		eventTemplate.EventDate = dateFallback
	}

	// Extract copyright owner
	copyrightOwner := common.FindStringWithoutMarkers(body, "- Representing", "\n")
	copyrightOwner = strings.TrimSpace(strings.TrimRight(copyrightOwner, "\r"))
	if parts := strings.Split(copyrightOwner, ": "); len(parts) > 1 {
		copyrightOwner = parts[1]
	}

	eventTemplate.EventTypes = []events.EventType{events.NewCopyright("", copyrightOwner, "")}

	var result []*events.Event

	// Check for multiple URLs
	if strings.Contains(body, "Neutralized URLs") {
		urlsText := common.FindStringWithoutMarkers(body, "Neutralized URLs:", "")
		allURLs := strings.Split(urlsText, ", ")
		for _, url := range allURLs {
			url = strings.TrimSpace(url)
			if common.IsURL(url) {
				// Deep copy the event template
				event := copyEvent(eventTemplate)
				event.URL = url
				result = append(result, event)
			}
		}
	} else if strings.Contains(body, "Neutralized URL") {
		url := common.FindStringWithoutMarkers(body, "Neutralized URL:", "")
		url = strings.TrimSpace(url)
		eventTemplate.URL = url
		result = append(result, eventTemplate)
	}

	return result, nil
}

// parseDateFromLine parses a date from a line matching the date pattern
// Format: 2022/09/01 12:18:34 UTC
func parseDateFromLine(line string) *time.Time {
	match := datePattern.FindStringSubmatch(line)
	if match == nil {
		return nil
	}

	// Try to parse the date string
	// The pattern extracts YYYY/MM/DD HH:MM:SS
	dateStr := match[0]
	// Remove " UTC" suffix if present
	dateStr = strings.TrimSuffix(dateStr, " UTC")
	dateStr = strings.TrimSpace(dateStr)

	// Try parsing with the format "2006/01/02 15:04:05"
	t, err := time.Parse("2006/01/02 15:04:05", dateStr)
	if err == nil {
		return &t
	}

	return nil
}

// parseEmailDate parses a date from email headers
func parseEmailDate(dateStr string) *time.Time {
	// Common email date formats
	formats := []string{
		time.RFC1123Z,
		time.RFC1123,
		time.RFC822Z,
		time.RFC822,
		"Mon, 2 Jan 2006 15:04:05 -0700",
		"Mon, 02 Jan 2006 15:04:05 -0700",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return &t
		}
	}

	return nil
}

// copyEvent creates a deep copy of an event
func copyEvent(src *events.Event) *events.Event {
	dst := events.NewEvent(src.Parser)
	dst.IP = src.IP
	dst.URL = src.URL
	dst.Port = src.Port
	dst.Domain = src.Domain
	dst.ReportID = src.ReportID
	dst.EventDate = src.EventDate
	dst.ReceivedDate = src.ReceivedDate
	dst.SendDate = src.SendDate
	dst.SenderEmail = src.SenderEmail
	dst.RecipientEmail = src.RecipientEmail

	// Copy event types
	if src.EventTypes != nil {
		dst.EventTypes = make([]events.EventType, len(src.EventTypes))
		copy(dst.EventTypes, src.EventTypes)
	}

	// Copy headers
	if src.Headers != nil {
		dst.Headers = make(map[string]interface{})
		for k, v := range src.Headers {
			dst.Headers[k] = v
		}
	}

	// Copy requirements
	if src.Requirements != nil {
		dst.Requirements = make(map[string]events.Requirement)
		for k, v := range src.Requirements {
			dst.Requirements[k] = v
		}
	}

	return dst
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
