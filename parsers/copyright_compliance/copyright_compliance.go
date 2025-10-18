package copyright_compliance

import (
	"fmt"
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

// parseEventDate converts date strings to time.Time
// Handles formats like "sep 22, 2024, 3:45 PM" or "September 22, 2024, 3:45 PM"
func parseEventDate(dateStr string) (*time.Time, error) {
	// Replace p.m. and a.m. with PM and AM
	eventDate := strings.ReplaceAll(dateStr, "p.m.", "PM")
	eventDate = strings.ReplaceAll(eventDate, "a.m.", "AM")

	// Take only the first line
	lines := strings.Split(eventDate, "\n")
	if len(lines) > 0 {
		eventDate = lines[0]
	}

	// Remove periods from abbreviated month names (e.g., "sep." -> "sep")
	re := regexp.MustCompile(`^([a-z]+)\.`)
	eventDate = re.ReplaceAllString(eventDate, "$1")

	// Replace "sept" with "sep" for parsing
	eventDate = strings.ReplaceAll(eventDate, "sept", "sep")

	// Determine format based on whether there's a colon (time with minutes)
	var shortFormat, longFormat string
	if strings.Contains(eventDate, ":") {
		shortFormat = "Jan 2, 2006, 3:04 PM"
		longFormat = "January 2, 2006, 3:04 PM"
	} else {
		shortFormat = "Jan 2, 2006, 3 PM"
		longFormat = "January 2, 2006, 3 PM"
	}

	// Try short format first
	t, err := time.Parse(shortFormat, eventDate)
	if err != nil {
		// Try long format
		t, err = time.Parse(longFormat, eventDate)
		if err != nil {
			return nil, fmt.Errorf("failed to parse date '%s': %w", dateStr, err)
		}
	}

	return &t, nil
}

// parseUrgentNoticeOfInfringement parses "urgent notice of infringement" emails
func parseUrgentNoticeOfInfringement(body, copyrightOwner string) ([]*events.Event, error) {
	// Replace smart quotes
	body = strings.ReplaceAll(body, "\u201c", "\"")
	body = strings.ReplaceAll(body, "\u201d", "\"")

	copyrightedWork := common.FindStringWithoutMarkers(body, "asset: ", "")
	noticeID := common.FindStringWithoutMarkers(body, "notice id: ", "")
	eventDateStr := common.FindStringWithoutMarkers(body, "timestamp: ", "")
	url := common.FindStringWithoutMarkers(body, "url: ", "")

	eventDate, err := parseEventDate(eventDateStr)
	if err != nil {
		return nil, err
	}

	event := events.NewEvent("copyright_compliance")
	event.URL = url
	event.EventDate = eventDate
	event.AddEventDetailSimple("notice_id", noticeID)
	event.EventTypes = []events.EventType{
		events.NewCopyright(copyrightedWork, copyrightOwner, ""),
	}

	return []*events.Event{event}, nil
}

// parseCopyrightInfringementNotice parses "copyright infringement notice" emails
func parseCopyrightInfringementNotice(subject, body, copyrightOwner string) ([]*events.Event, error) {
	eventDateStr := common.FindStringWithoutMarkers(body, "access was present on ", ". please act")
	eventDate, err := parseEventDate(eventDateStr)
	if err != nil {
		return nil, err
	}

	// Notice ID is the last word in the subject
	parts := strings.Fields(subject)
	noticeID := ""
	if len(parts) > 0 {
		noticeID = parts[len(parts)-1]
	}

	// Extract copyrighted works
	copyrightedWorkLines := common.GetBlockAfterWithStop(body, "copyrighted work(s) infringed upon:", "location of infringing material:",
	)

	var copyrightedWorks []string
	for _, line := range copyrightedWorkLines {
		cleaned := strings.TrimPrefix(line, "- ")
		if cleaned != "" {
			copyrightedWorks = append(copyrightedWorks, cleaned)
		}
	}
	copyrightedWork := fmt.Sprintf("%v", copyrightedWorks)

	// Extract URLs
	urlLines := common.GetBlockAfterWithStop(body, "location of infringing material:", "i have a good faith belief",
	)

	var eventsResult []*events.Event
	for _, line := range urlLines {
		url := strings.TrimPrefix(line, "- ")
		if url == "" {
			continue
		}

		event := events.NewEvent("copyright_compliance")
		event.EventDate = eventDate
		event.URL = url
		event.AddEventDetailSimple("notice_id", noticeID)
		event.EventTypes = []events.EventType{
			events.NewCopyright(copyrightedWork, copyrightOwner, ""),
		}
		eventsResult = append(eventsResult, event)
	}

	return eventsResult, nil
}

// parseInfringementOf parses "infringement of" emails
func parseInfringementOf(body, copyrightOwner string) ([]*events.Event, error) {
	eventDateStr := common.FindStringWithoutMarkers(body, "date: ", "")
	eventDate, err := parseEventDate(eventDateStr)
	if err != nil {
		return nil, err
	}

	noticeIDRaw := common.FindStringWithoutMarkers(body, "notice id: ", "")
	lines := strings.Split(noticeIDRaw, "\n")
	noticeID := ""
	if len(lines) > 0 {
		noticeID = lines[0]
	}

	// Extract copyrighted works
	copyrightedWorkLines := common.GetBlockAfterWithStop(body, "representative list of titles:", "examples of locations",
	)

	var copyrightedWorks []string
	for _, line := range copyrightedWorkLines {
		cleaned := strings.TrimPrefix(line, "- ")
		if cleaned != "" {
			copyrightedWorks = append(copyrightedWorks, cleaned)
		}
	}
	copyrightedWork := fmt.Sprintf("%v", copyrightedWorks)

	// Extract URLs - using empty stopMarker to continue until end
	urlLines := common.GetBlockAfterWithStop(body, "examples of locations where infringing materials can be found:", "",
	)

	var eventsResult []*events.Event
	for _, line := range urlLines {
		url := strings.TrimPrefix(line, "- ")
		if url == "" {
			continue
		}

		event := events.NewEvent("copyright_compliance")
		event.EventDate = eventDate
		event.URL = url
		event.AddEventDetailSimple("notice_id", noticeID)
		event.EventTypes = []events.EventType{
			events.NewCopyright(copyrightedWork, copyrightOwner, ""),
		}
		eventsResult = append(eventsResult, event)
	}

	return eventsResult, nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	body = strings.ToLower(body)

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	subject = strings.ToLower(subject)
	// Join multiline subject into single line
	subject = strings.Join(strings.Fields(subject), " ")

	// Replace smart quotes
	body = strings.ReplaceAll(body, "\u201c", "\"")
	body = strings.ReplaceAll(body, "\u201d", "\"")

	// Extract copyright owner
	copyrightOwner := common.FindStringWithoutMarkers(body, "affiliated companies (\"", "\"),")

	// Determine which parser to use based on subject
	if strings.Contains(subject, "urgent notice of infringement") {
		return parseUrgentNoticeOfInfringement(body, copyrightOwner)
	} else if strings.Contains(subject, "copyright infringement notice") {
		return parseCopyrightInfringementNotice(subject, body, copyrightOwner)
	} else if strings.Contains(subject, "infringement of") {
		return parseInfringementOf(body, copyrightOwner)
	} else {
		return nil, common.NewNewTypeError(subject)
	}
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
