package dmca_pro

import (
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
	// Get body, trying main body first, then first part if body is empty
	body, _ := common.GetBody(serializedEmail, false)
	if strings.TrimSpace(body) == "" && len(serializedEmail.Parts) > 0 {
		if partBody, ok := serializedEmail.Parts[0].Body.(string); ok {
			body = partBody
		}
	}

	if body == "" {
		return nil, nil
	}

	var resultEvents []*events.Event

	// Get date from headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	// Parse body line by line
	lines := strings.Split(body, "\n")
	var urlList []string
	copyrightedURL := ""
	name := ""

	for i := 0; i < len(lines); i++ {
		// Strip <p> tags
		lines[i] = strings.TrimPrefix(lines[i], "<p>")

		// Look for URL list after "These exclusive rights"
		if strings.HasPrefix(lines[i], "These exclusive rights") {
			if i+1 < len(lines) {
				index := i + 1
				urlString := strings.TrimSuffix(lines[index], "</p>")
				urlList = strings.Split(urlString, "<br />")
			}
		} else if strings.HasPrefix(lines[i], "Pursuant to") {
			// Extract copyrighted work name and URL
			// Format: "Pursuant to ... for {name} from {url}"
			parts := strings.Split(lines[i], " from ")
			if len(parts) >= 2 {
				namePart := parts[0]
				copyrightedURLPart := parts[1]

				// Extract URL from HTML
				copyrightedStartIndex := strings.Index(copyrightedURLPart, ">") + 1
				if copyrightedStartIndex > 0 {
					copyrightedEndIndex := strings.Index(copyrightedURLPart[copyrightedStartIndex:], "<")
					if copyrightedEndIndex != -1 {
						copyrightedURL = copyrightedURLPart[copyrightedStartIndex : copyrightedStartIndex+copyrightedEndIndex]
					}
				}

				// Extract name after " for "
				forParts := strings.Split(namePart, " for ")
				if len(forParts) >= 2 {
					name = forParts[len(forParts)-1]
				}
			}
		}
	}

	// Create one event per URL
	for _, url := range urlList {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}

		event := events.NewEvent("dmca_pro")
		event.URL = url
		event.EventDate = eventDate

		// Create Copyright event type with official URL and copyrighted work
		copyright := &events.Copyright{
			BaseEventType: events.BaseEventType{
				Name: "copyright",
				Type: "copyright",
			},
			OfficialURL:     copyrightedURL,
			CopyrightedWork: strings.Trim(name, "&#8201;"),
		}
		event.EventTypes = []events.EventType{copyright}

		resultEvents = append(resultEvents, event)
	}

	return resultEvents, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
