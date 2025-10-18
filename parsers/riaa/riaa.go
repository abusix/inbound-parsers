package riaa

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
	urlPattern = regexp.MustCompile(`http\S+`)
)

func NewParser() *Parser {
	return &Parser{}
}

// removeHTML removes HTML tags from a string
func removeHTML(s string) string {
	// Remove all HTML tags
	s = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(s, "")
	return s
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	body = removeHTML(body)

	// Create event template with event date from header
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	var results []*events.Event

	// Process each line
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "http") {
			// Line starts with URL
			parts := strings.SplitN(line, " ", 2)
			url := parts[0]

			event := events.NewEvent("riaa")
			event.EventDate = eventDate
			event.URL = url

			// Extract copyrighted work name if present
			var name string
			if len(parts) > 1 {
				name = parts[1]
				name = strings.ReplaceAll(name, "<br>", "")
				name = strings.ReplaceAll(name, "<br />", "")
				name = strings.TrimSpace(name)
			}

			event.EventTypes = []events.EventType{events.NewCopyright(name, "", "")}
			results = append(results, event)
		} else if match := urlPattern.FindString(line); match != "" {
			// Line contains a URL somewhere
			event := events.NewEvent("riaa")
			event.EventDate = eventDate
			event.URL = match
			event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}
			results = append(results, event)
		}
	}

	if len(results) == 0 {
		return nil, common.NewParserError("no URLs found in email body")
	}

	return results, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
