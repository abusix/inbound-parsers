package miglisoft

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	pkgemail "github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *pkgemail.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)

	// Replace <br> with newlines
	body = strings.ReplaceAll(body, "<br>", "\n")

	// Extract URLs that start with "http" from the block after "infringing content can be found at:"
	urlsBlock := common.GetBlockAfterWithStop(body, "infringing content can be found at:", "")
	var urls []string
	for _, line := range urlsBlock {
		if strings.HasPrefix(line, "http") {
			urls = append(urls, line)
		}
	}

	// Extract original work URL
	originalWork := common.GetNonEmptyLineAfter(body, "original work at:")

	// Create Copyright event type with official URL
	copyright := events.NewCopyright("", "", "")
	copyright.OfficialURL = originalWork

	// Create events for each infringing URL
	var evts []*events.Event
	for _, url := range urls {
		event := events.NewEvent("miglisoft")
		event.EventTypes = []events.EventType{copyright}
		event.URL = url

		// Set event date from email headers
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = pkgemail.ParseDate(dateHeaders[0])
		}

		evts = append(evts, event)
	}

	return evts, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
