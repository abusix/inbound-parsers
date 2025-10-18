package fsm

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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)

	// Create event template with common fields
	eventTemplate := events.NewEvent("fsm")
	eventTemplate.EventTypes = []events.EventType{events.NewChildAbuse()}

	// Extract and parse event date
	dateString := common.FindStringWithoutMarkers(bodyLower, "date/time assessed:", "")
	dateString = strings.TrimSpace(dateString)

	var eventDate *time.Time
	if dateString != "" {
		// Try to parse with email.ParseDate (handles multiple formats)
		eventDate = email.ParseDate(dateString)

		// If that fails, try German date format DD.MM.YYYY
		if eventDate == nil {
			if parsedDate, err := time.Parse("02.01.2006", dateString); err == nil {
				eventDate = &parsedDate
			}
		}
	}

	// Fallback to email header date if parsing failed
	if eventDate == nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventDate = email.ParseDate(dateHeaders[0])
		}
	}

	eventTemplate.EventDate = eventDate

	// Extract external ID
	externalID := common.FindStringWithoutMarkers(bodyLower, "hotline unique report number:", "")
	externalID = strings.TrimSpace(externalID)
	if externalID != "" {
		eventTemplate.AddEventDetail(&events.ExternalID{ID: externalID})
	}

	// Extract IP address
	var ipAddress string
	if ip := common.FindStringWithoutMarkers(bodyLower, "ip address:", ""); ip != "" {
		ipAddress = strings.TrimSpace(ip)
	} else if ip := common.FindStringWithoutMarkers(bodyLower, "löst zur ip", ""); ip != "" {
		ipAddress = strings.TrimSpace(ip)
	}

	// Clean up IP if found
	if ipAddress != "" {
		ipAddress = common.ExtractOneIP(ipAddress)
	}

	// Extract URLs
	var urls []string
	urlBlock := common.FindStringWithoutMarkers(bodyLower, "url(s):", "in coordination with")
	if urlBlock != "" {
		lines := strings.Split(urlBlock, "\n")
		for _, line := range lines {
			trimmedLine := strings.TrimSpace(line)
			if strings.HasPrefix(trimmedLine, "http") {
				urls = append(urls, trimmedLine)
			}
		}
	}

	// If no URLs found in block, try single URL extraction
	if len(urls) == 0 {
		singleURL := common.FindStringWithoutMarkers(bodyLower, "unter der url", "eine beschwerde erhalten")
		singleURL = strings.TrimSpace(singleURL)

		// Only create events if we have either a URL or IP
		if singleURL != "" || ipAddress != "" {
			event := copyEventTemplate(eventTemplate)
			if singleURL != "" {
				event.URL = singleURL
			}
			if ipAddress != "" {
				event.IP = ipAddress
			}
			return []*events.Event{event}, nil
		}

		// No URLs and no IP found
		return []*events.Event{}, nil
	}

	// Create one event per URL
	var results []*events.Event
	for _, url := range urls {
		event := copyEventTemplate(eventTemplate)
		event.URL = url
		if ipAddress != "" {
			event.IP = ipAddress
		}
		results = append(results, event)
	}

	return results, nil
}

// copyEventTemplate creates a deep copy of the event template
func copyEventTemplate(template *events.Event) *events.Event {
	event := events.NewEvent(template.Parser)
	event.EventTypes = template.EventTypes
	event.EventDate = template.EventDate

	// Copy event details
	if len(template.EventDetails) > 0 {
		event.EventDetails = make([]events.EventDetail, len(template.EventDetails))
		copy(event.EventDetails, template.EventDetails)
	}

	return event
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
