package removal_request

import (
	"fmt"
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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	event := events.NewEvent("removal_request")

	// Try to get event_date from headers first
	if serializedEmail.Headers != nil {
		if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
			if parsedDate := email.ParseDate(dateHeader[0]); parsedDate != nil {
				event.EventDate = parsedDate
			}
		}
	}

	// If no date in headers, parse from body
	if event.EventDate == nil {
		lines := strings.Split(body, "\n")
		if len(lines) > 1 {
			// Parse date from second line (index 1) in format: MM/DD/YY
			dateParts := strings.Split(strings.TrimSpace(lines[1]), "/")
			if len(dateParts) == 3 {
				month := dateParts[0]
				day := dateParts[1]
				year := dateParts[2]

				// Construct ISO format: 20YY-MM-DDTHH:MM:SS
				now := time.Now().UTC()
				dateStr := fmt.Sprintf("20%s-%s-%sT%02d:%02d:%02d",
					year, month, day,
					now.Hour(), now.Minute(), now.Second())

				if parsedDate, err := time.Parse("2006-01-02T15:04:05", dateStr); err == nil {
					event.EventDate = &parsedDate
				}
			}
		}
	}

	// Extract stream information
	stream := common.FindStringWithoutMarkers(body, "unauthorized stream of ", " is available")
	stream = strings.Trim(stream, "\" ")

	// Extract copyright owner
	copyrightOwner := common.FindStringWithoutMarkers(body, "on behalf of ", ".")

	// Extract URL
	url := common.GetNonEmptyLineAfter(body, "the following URL:")
	event.URL = url

	// Set event types with Copyright
	event.EventTypes = []events.EventType{
		events.NewCopyright(stream, copyrightOwner, ""),
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
