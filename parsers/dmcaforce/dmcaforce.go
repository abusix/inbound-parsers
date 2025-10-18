package dmcaforce

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
	// Get body with throws=True to match Python behavior
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	if body == "" {
		return nil, common.NewParserError("no email body found")
	}

	// Get event date from headers
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	// Split body into lines (splitlines(False) in Python means keep newlines)
	// Using strings.Split in Go already removes the newline characters
	lines := strings.Split(body, "\n")

	var infringingURLs []string
	var owner string

	// Iterate through lines to find copyright owner and URLs
	for i := 0; i < len(lines); i++ {
		line := lines[i]

		// Extract copyright owner
		if strings.HasPrefix(line, "Copyright Owner Name: ") {
			// Python: _, _, owner = split[i].partition('Copyright Owner Name: ')
			// partition returns (before, separator, after), we want "after"
			owner = strings.TrimPrefix(line, "Copyright Owner Name: ")
		}

		// Find URL sections
		if strings.HasPrefix(line, "The following works") ||
			strings.HasPrefix(line, "URL(s) of copyrighted works") ||
			strings.HasPrefix(line, "URLs:") {

			// Extract URLs starting from i+2 (skip current line and next blank line)
			for index := i + 2; index < len(lines); index++ {
				if !strings.HasPrefix(lines[index], "http") {
					break
				}
				infringingURLs = append(infringingURLs, lines[index])
			}
		}
	}

	// Create one event per infringing URL
	var result []*events.Event
	for _, url := range infringingURLs {
		event := events.NewEvent("dmcaforce")
		event.EventDate = eventDate
		event.URL = url
		event.EventTypes = []events.EventType{events.NewCopyright("", owner, "")}
		result = append(result, event)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
