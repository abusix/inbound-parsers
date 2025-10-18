// Package expressvpn implements the expressvpn parser
package expressvpn

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the expressvpn parser
type Parser struct{}

// Parse parses emails from enforcement@expressvpn.com for copyright infringement notices
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Validate subject
	if !strings.Contains(subject, "Infringement Notice") {
		return nil, common.NewParserError("expected 'Infringement Notice' in subject, got: " + subject)
	}

	// Create event template
	eventTemplate := events.NewEvent("expressvpn")

	// Set event date from email header
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventTemplate.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Normalize body
	body = strings.ReplaceAll(body, "\r\n", "\n")
	body = strings.ReplaceAll(body, ":\n", ":\n\n")

	// Extract reporter organization details
	companyInfo := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Company Name:", ""))
	address := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Mailing address:", ""))
	contactName := strings.TrimSpace(common.FindStringWithoutMarkers(body, "\nName:", ""))
	emailAddr := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Email:", ""))
	phone := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Phone:", ""))

	// Add organization information
	org := &events.Organisation{
		Name:         "reporter",
		Organisation: companyInfo,
		Address:      address,
		ContactEmail: emailAddr,
		ContactPhone: phone,
		ContactName:  contactName,
	}
	eventTemplate.AddEventDetail(org)

	// Add external ID
	externalID := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Current Issue:", ""))
	if externalID != "" {
		extID := &events.ExternalID{
			ID: externalID,
		}
		eventTemplate.AddEventDetail(extID)
	}

	// Set event type to copyright
	eventTemplate.EventTypes = []events.EventType{events.NewCopyright("", "", "")}

	// Extract URLs from section 2)
	reportBlock := common.GetBlockAfterWithStop(body, "2)", "")

	var result []*events.Event
	for _, url := range reportBlock {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}
		// Create a copy of the event for each URL
		event := copyEvent(eventTemplate)
		event.URL = url
		result = append(result, event)
	}

	return result, nil
}

// copyEvent creates a deep copy of an event
func copyEvent(template *events.Event) *events.Event {
	event := events.NewEvent("expressvpn")
	event.EventDate = template.EventDate
	event.URL = template.URL
	event.IP = template.IP
	event.Port = template.Port

	// Copy event types
	event.EventTypes = make([]events.EventType, len(template.EventTypes))
	copy(event.EventTypes, template.EventTypes)

	// Copy event details
	for _, detail := range template.EventDetails {
		event.EventDetails = append(event.EventDetails, detail)
	}

	return event
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
