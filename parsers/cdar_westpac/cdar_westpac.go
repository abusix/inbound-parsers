package cdar_westpac

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

	// Get date from email headers
	var date *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		date = email.ParseDate(dateHeaders[0])
	}

	// Extract IPs
	ips := common.GetBlockAfterWithStop(body, "IP address(es)", "")
	if len(ips) == 0 {
		ip := common.FindStringWithoutMarkers(body, "IP address", "")
		if ip != "" {
			ips = []string{ip}
		}
	}

	// Extract URLs
	urls := common.GetBlockAfterWithStop(body, "following URL(s)", "")
	if len(urls) == 0 {
		url := common.GetNonEmptyLineAfter(body, "following URL:")
		url = strings.Trim(url, "-\t ")
		if url != "" {
			urls = []string{url}
		}
	}

	// Extract external ID from subject
	externalID := common.FindStringWithoutMarkers(subject, "[REF #", "]")

	// If URL count doesn't match IP count, use first URL for all IPs
	if len(urls) != len(ips) && len(urls) > 0 {
		firstURL := urls[0]
		urls = make([]string, len(ips))
		for i := range urls {
			urls[i] = firstURL
		}
	}

	// Create events for each IP/URL pair
	var result []*events.Event
	for i, ip := range ips {
		var url string
		if i < len(urls) {
			url = urls[i]
		}

		event := events.NewEvent("cdar_westpac")

		// Add external ID if present
		if externalID != "" {
			event.AddEventDetail(&events.ExternalID{ID: externalID})
		}

		event.EventTypes = []events.EventType{events.NewPhishing()}
		event.EventDate = date
		event.IP = ip
		event.URL = url

		result = append(result, event)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
