package domainoo

import (
	"fmt"
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
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	subjectLower := strings.ToLower(subject)

	// Create base event template
	eventTemplate := events.NewEvent("domainoo")

	// Set event date from email headers
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventTemplate.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Determine event type
	if strings.Contains(subjectLower, "trademark") || strings.Contains(body, "trademark") {
		trademarkOwner := common.FindStringWithoutMarkers(subjectLower, "infringement of ", " trademark")
		eventTemplate.EventTypes = []events.EventType{
			&events.Trademark{
				BaseEventType: events.BaseEventType{
					Name: "trademark",
					Type: "trademark",
				},
				TrademarkOwner: trademarkOwner,
			},
		}
	} else {
		return nil, fmt.Errorf("new type error: %s", subjectLower)
	}

	// Extract external ID/reference number
	externalID := common.FindStringWithoutMarkers(body, "Our reference No: ", "\n")
	if externalID != "" {
		eventTemplate.AddEventDetail(&events.ExternalID{
			ID: strings.TrimSpace(externalID),
		})
	}

	var result []*events.Event

	// Extract URLs - try multiple patterns
	// Pattern 1: "Domain names: url1 url2 url3"
	if urls := common.FindStringWithoutMarkers(body, "Domain names: ", ""); urls != "" {
		urlList := strings.Fields(urls)
		for _, url := range urlList {
			if url != ";" && url != "and" {
				event := copyEvent(eventTemplate)
				event.URL = url
				result = append(result, event)
			}
		}
		return result, nil
	}

	// Pattern 2: "url has been registered by your client"
	urlPattern := regexp.MustCompile(`(?P<url>\S+)\s+(has)*\s*(been)*\s*registered by your client`)
	if match := urlPattern.FindStringSubmatch(body); match != nil {
		event := copyEvent(eventTemplate)
		event.URL = match[1]
		return []*events.Event{event}, nil
	}

	// Pattern 3: "Domain name: url"
	if url := common.FindStringWithoutMarkers(body, "Domain name: ", ""); url != "" {
		eventTemplate.URL = url
		return []*events.Event{eventTemplate}, nil
	}

	// Pattern 4: "URL: url"
	if url := common.FindStringWithoutMarkers(body, "URL: ", ""); url != "" {
		eventTemplate.URL = url
		return []*events.Event{eventTemplate}, nil
	}

	// If no URL found, return the template anyway
	return []*events.Event{eventTemplate}, nil
}

// copyEvent creates a deep copy of an event
func copyEvent(template *events.Event) *events.Event {
	event := events.NewEvent(template.Parser)
	event.IP = template.IP
	event.URL = template.URL
	event.Port = template.Port
	event.Domain = template.Domain
	event.ReportID = template.ReportID
	event.EventTypes = template.EventTypes
	event.EventDate = template.EventDate
	event.ReceivedDate = template.ReceivedDate
	event.SendDate = template.SendDate
	event.SenderEmail = template.SenderEmail
	event.RecipientEmail = template.RecipientEmail

	// Copy event details
	for _, detail := range template.EventDetails {
		event.EventDetails = append(event.EventDetails, detail)
	}

	// Copy headers
	if template.Headers != nil {
		event.Headers = make(map[string]interface{})
		for k, v := range template.Headers {
			event.Headers[k] = v
		}
	}

	// Copy requirements
	if template.Requirements != nil {
		event.Requirements = make(map[string]events.Requirement)
		for k, v := range template.Requirements {
			event.Requirements[k] = v
		}
	}

	return event
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
