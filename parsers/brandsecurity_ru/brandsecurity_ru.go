package brandsecurity_ru

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

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Replace HTML tags with newlines (similar to Python re.sub)
	brTagPattern := regexp.MustCompile(`</?((br)|p)>`)
	body = brTagPattern.ReplaceAllString(body, "\n")

	// Extract URLs
	var urls []string
	url := common.GetNonEmptyLineAfter(body, "Copyright Holder for the trademarks:")
	if url == "" {
		url = common.GetNonEmptyLineAfter(body, "trademarks of the Copyright Holder:")
	}
	if url == "" {
		urls = common.GetContinuousLinesUntilEmptyLine(body, "hosting services violates intellectual property rights.")
	} else {
		urls = []string{strings.TrimSpace(url)}
	}

	var resultEvents []*events.Event

	// Process each URL
	for _, url := range urls {
		event := events.NewEvent("brandsecurity_ru")

		// Set event date from email headers
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}

		event.URL = url

		// Extract owner
		owner := common.FindStringWithoutMarkers(body, " the interests of «", "»")
		owner = strings.TrimSpace(owner)
		if owner == "" {
			owner = common.FindStringWithoutMarkers(body, " the interests of <strong>", "</strong>")
			owner = strings.TrimSpace(owner)
		}

		var nr []string
		if owner == "" {
			// Extract from block
			lines := common.GetBlockAfter(
				body,
				"including protection of rights to copyright and intellectual property objects and trademarks",
				"",
			)
			for _, line := range lines {
				if owner == "" {
					candidate := common.FindStringWithoutMarkers(line, "«", "»")
					if candidate != "" {
						owner = candidate
					}
				}
				result := common.FindStringWithoutMarkers(line, "RU No. ", " ")
				if result != "" {
					nr = append(nr, result)
				}
			}
		}

		// Create Trademark event type
		event.EventTypes = []events.EventType{
			events.NewTrademark("russia", nr, owner, ""),
		}

		resultEvents = append(resultEvents, event)
	}

	return resultEvents, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
