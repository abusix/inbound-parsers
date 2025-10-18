package secureserver

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/parsers/common"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)

	// Get event date from email headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	var result []*events.Event

	// Check if body contains 'trademark'
	if strings.Contains(bodyLower, "trademark") {
		// Try to get URL from "example of infringing url's" section
		if url := common.GetNonEmptyLineAfter(bodyLower, "example of infringing url's"); url != "" {
			event := events.NewEvent("secureserver")
			event.EventDate = eventDate
			event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}
			event.URL = url
			result = append(result, event)
		} else {
			// Try to extract URL and IP using regex pattern
			// Pattern: http\S+\s+\S+\s+(\d|\.)+
			pattern := regexp.MustCompile(`(?P<url>http\S+)\s+\S+\s+(?P<ip>(\d|\.)+)`)
			if match := pattern.FindStringSubmatch(bodyLower); match != nil {
				urlIdx := pattern.SubexpIndex("url")
				ipIdx := pattern.SubexpIndex("ip")

				if urlIdx != -1 && ipIdx != -1 && urlIdx < len(match) && ipIdx < len(match) {
					event := events.NewEvent("secureserver")
					event.EventDate = eventDate
					event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}
					event.URL = match[urlIdx]
					event.IP = match[ipIdx]
					result = append(result, event)
				}
			}
		}
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
