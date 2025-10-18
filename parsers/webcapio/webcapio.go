package webcapio

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
	body, _ := common.GetBody(serializedEmail, false)

	// Get header date
	var headerDate string
	if date, ok := serializedEmail.Headers["date"]; ok && len(date) > 0 {
		headerDate = date[0]
	}

	// Extract reference ID
	ref := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Ref:", ""))

	var eventsList []*events.Event

	bodyLower := strings.ToLower(body)

	// Check for first format: "following url(s)" and "the information"
	if strings.Contains(bodyLower, "following url(s)") && strings.Contains(bodyLower, "the information") {
		urlSection := common.FindStringWithoutMarkers(bodyLower, "following url(s)", "the information")
		lines := strings.Split(urlSection, "\n")

		for _, line := range lines {
			if strings.Contains(line, "http") {
				event := events.NewEvent("webcapio")
				event.EventDate = email.ParseDate(headerDate)
				event.URL = strings.TrimSpace(line)

				copyright := events.NewCopyright("", "", "")
				event.EventTypes = []events.EventType{copyright}

				if ref != "" {
					event.AddEventDetail(&events.ExternalID{ID: ref})
				}

				eventsList = append(eventsList, event)
			}
		}
	} else if strings.Contains(body, "Re:") {
		// Check for second format: "Re:" with URL - Artist - Title
		line := common.GetNonEmptyLineAfter(body, "Re:")
		parts := strings.Split(line, " - ")

		if len(parts) >= 3 {
			url := strings.TrimSpace(parts[0])
			artist := strings.TrimSpace(parts[1])
			title := strings.TrimSpace(parts[2])

			event := events.NewEvent("webcapio")
			event.EventDate = email.ParseDate(headerDate)
			event.URL = url

			copyright := events.NewCopyright(title, artist, "")
			event.EventTypes = []events.EventType{copyright}

			if ref != "" {
				event.AddEventDetail(&events.ExternalID{ID: ref})
			}

			eventsList = append(eventsList, event)
		}
	} else {
		// Check for third format: books/magazines/newspapers/scores
		startsWith := "In this particular case, we refer to the book(s)/magazine(s)/newspaper(s)/score(s):"
		owners := strings.TrimSpace(common.FindStringWithoutMarkers(body, startsWith, "published by"))
		endsWith := "available through the following"
		works := strings.TrimSpace(common.FindStringWithoutMarkers(body, "published by", endsWith))

		urls := common.GetContinuousLinesUntilEmptyLine(body, "following link of your website:")
		for _, line := range urls {
			trimmedURL := strings.TrimSpace(line)
			if trimmedURL != "" {
				event := events.NewEvent("webcapio")
				event.EventDate = email.ParseDate(headerDate)
				event.URL = trimmedURL

				copyright := events.NewCopyright(works, owners, "")
				event.EventTypes = []events.EventType{copyright}

				eventsList = append(eventsList, event)
			}
		}
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
