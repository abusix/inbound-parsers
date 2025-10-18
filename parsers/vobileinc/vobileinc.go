package vobileinc

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
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Extract URLs from "outstanding links:" section
	urls := common.GetBlockAfter(body, "outstanding links:")

	// Extract AS number from subject line (between "AS" and " ")
	asNumber := common.FindStringWithoutMarkers(subject, "AS", " ")

	// Extract AS name from body (between AS number and ",")
	asName := strings.TrimSpace(common.FindStringWithoutMarkers(body, asNumber, ","))

	// Extract behalf from body (between "on behalf of" and ".")
	behalf := strings.TrimSpace(common.FindStringWithoutMarkers(body, "on behalf of", "."))

	// Extract IP from second line of body
	lines := strings.Split(body, "\n")
	ip := ""
	if len(lines) > 1 {
		ip = common.IsIP(common.ExtractOneIP(lines[1]))
	}

	// Get event date from headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	var result []*events.Event

	// Create an event for each URL that contains "http"
	for _, url := range urls {
		if strings.Contains(url, "http") {
			event := events.NewEvent("vobileinc")
			event.URL = url
			event.IP = ip
			event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}
			event.EventDate = eventDate

			// Add ASN event detail
			if asNumber != "" {
				event.AddEventDetail(&events.ASN{
					ASN:    asNumber,
					ASName: asName,
				})
			}

			// Add OnBehalfOf event detail
			if behalf != "" {
				event.AddEventDetail(&events.OnBehalfOf{
					ComplainantContact: behalf,
				})
			}

			result = append(result, event)
		}
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
