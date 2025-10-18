package ciu_online

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
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	// Check subject contains 'infringing'
	if !strings.Contains(strings.ToLower(subject), "infringing") {
		return nil, fmt.Errorf("subject does not contain 'infringing': %s", subject)
	}

	bodyLower := strings.ToLower(body)

	// Extract fields
	date := strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "date:", "\n"))
	externalID := strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "case #:", "\n"))
	ip := strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "ip address:", "\n"))

	// Extract works and URLs using GetBlockAfter
	works := common.GetBlockAfterWithStop(bodyLower, "copyright work(s):", "following location(s):")
	urls := common.GetBlockAfterWithStop(bodyLower, "following location(s):", "")

	// If there's one work and multiple URLs, duplicate the work
	if len(works) == 1 && len(urls) > 1 {
		singleWork := works[0]
		works = make([]string, len(urls))
		for i := range works {
			works[i] = singleWork
		}
	}

	// Create events for each work/URL pair
	var result []*events.Event

	// Use zip_longest behavior - iterate over the longer list
	maxLen := len(works)
	if len(urls) > maxLen {
		maxLen = len(urls)
	}

	for i := 0; i < maxLen; i++ {
		event := events.NewEvent("ciu_online")

		// Add external ID
		if externalID != "" {
			event.AddEventDetail(&events.ExternalID{ID: externalID})
		}

		// Add copyright work if available
		var work string
		if i < len(works) {
			work = works[i]
		}
		event.EventTypes = []events.EventType{events.NewCopyright(work, "", "")}

		// Parse and set event date
		if date != "" {
			// Python adds ' 00:00:00' to the date
			dateTimeStr := date + " 00:00:00"
			// Try common date formats
			formats := []string{
				"2006-01-02 15:04:05",
				"01/02/2006 15:04:05",
				"02/01/2006 15:04:05",
				"2006/01/02 15:04:05",
			}
			for _, format := range formats {
				if t, err := time.Parse(format, dateTimeStr); err == nil {
					event.EventDate = &t
					break
				}
			}
		}

		// Add URL if available
		if i < len(urls) {
			event.URL = urls[i]
		}

		// Add IP
		if ip != "" {
			event.IP = ip
		}

		result = append(result, event)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
