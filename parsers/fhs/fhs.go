package fhs

import (
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
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	bodyLower := strings.ToLower(body)

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Extract URL from body
	url := common.FindStringWithoutMarkers(bodyLower, "main url:", "")
	url = strings.TrimSpace(url)

	// Extract IPs from body (comma-separated list)
	ipsStr := common.FindStringWithoutMarkers(bodyLower, "ip address:", "")
	ips := strings.Split(ipsStr, ",")

	// Extract external ID from subject (format: "...#<id>")
	externalID := ""
	if parts := strings.Split(subject, "#"); len(parts) > 1 {
		externalID = parts[1]
	}

	// Get event date from email headers
	dateFallback := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateFallback = dateHeaders[0]
	}

	var result []*events.Event

	// Create one event per IP
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}

		event := events.NewEvent("fhs")
		event.IP = ip
		event.EventDate = email.ParseDate(dateFallback)
		event.URL = url

		// Add external ID if present
		if externalID != "" {
			extID := &events.ExternalID{
				ID: externalID,
			}
			event.AddEventDetail(extID)
		}

		// Set event type to Trademark with owner 'FH'
		trademark := events.NewTrademark("", []string{}, "FH", "")
		event.EventTypes = []events.EventType{trademark}

		result = append(result, event)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
