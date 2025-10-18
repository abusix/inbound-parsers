package notificationofinfringement

import (
	"strings"

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

	// Get header date
	var headerDate string
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		headerDate = dateHeader[0]
	}

	if strings.Contains(subject, "Notification of Infringement") {
		return parseNormalVersion(body, headerDate)
	}
	return parseBrokenVersion(body, headerDate, subject)
}

// getTextLinebreak determines the line break type used in the text
func getTextLinebreak(text string) string {
	if strings.Contains(text, "\r\n") {
		return "\r\n"
	}
	return "\n"
}

func parseBrokenVersion(body, headerDate, subject string) ([]*events.Event, error) {
	lineBreak := getTextLinebreak(body)

	officialURL := strings.TrimSpace(common.GetNonEmptyLineAfter(body, "Location of Original Works:"))

	// Extract external ID from subject
	var externalID string
	if idx := strings.Index(subject, "Notice"); idx != -1 {
		externalID = strings.TrimSpace(subject[idx+7:])
	}

	owners := strings.TrimSpace(common.GetNonEmptyLineAfter(body, "Copyright Holder(s):"))
	works := strings.TrimSpace(common.GetNonEmptyLineAfter(body, "The work in question"))
	ip := strings.TrimSpace(common.FindStringWithoutMarkers(body, "( IP ", ")"))

	urlPart := strings.TrimSpace(common.FindStringWithoutMarkers(body, "following URL(s):", "Truthfully"))

	if urlPart == "" {
		return nil, common.NewParserError("no infringing urls found")
	}

	var eventsList []*events.Event

	// Parse URLs - split by double line breaks
	doubleLineBreak := lineBreak + lineBreak
	urlList := strings.Split(urlPart, doubleLineBreak)

	for _, urlRaw := range urlList {
		// Remove line breaks within each URL and trim
		url := strings.TrimSpace(strings.ReplaceAll(urlRaw, lineBreak, ""))
		if url == "" {
			continue
		}

		event := events.NewEvent("notificationofinfringement")
		event.EventDate = email.ParseDate(headerDate)
		event.URL = url
		event.IP = ip

		// Add external ID if present
		if externalID != "" {
			event.AddEventDetail(&events.ExternalID{ID: externalID})
		}

		// Create copyright event type
		copyright := events.NewCopyright(works, owners, "")
		copyright.OfficialURL = officialURL
		event.EventTypes = []events.EventType{copyright}

		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no infringing urls found")
	}

	return eventsList, nil
}

func parseNormalVersion(body, headerDate string) ([]*events.Event, error) {
	lineBreak := getTextLinebreak(body)

	owners := common.FindStringWithoutMarkers(body, "on behalf of ", " for purposes of")

	// Extract copyrighted works and remove line breaks from the middle
	worksRaw := common.FindStringWithoutMarkers(body, "known as: ", " (the \"Properties\").")
	works := strings.ReplaceAll(worksRaw, lineBreak+" ", "")

	// Extract URLs part
	urlPart := common.FindStringWithoutMarkers(body, "following URLs:"+lineBreak, lineBreak+lineBreak)

	if urlPart == "" {
		return nil, common.NewParserError("no infringing urls found")
	}

	var eventsList []*events.Event

	// Parse URLs - split by newlines
	lines := strings.Split(strings.TrimSpace(urlPart), "\n")
	for _, url := range lines {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}

		event := events.NewEvent("notificationofinfringement")
		event.EventDate = email.ParseDate(headerDate)
		event.URL = url

		// Create copyright event type
		copyright := events.NewCopyright(works, owners, "")
		event.EventTypes = []events.EventType{copyright}

		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no infringing urls found")
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
