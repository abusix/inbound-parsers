// Package oplium implements the Oplium parser
package oplium

import (
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the Oplium parser
type Parser struct{}

// Parse parses emails from takedown@oplium.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	event := events.NewEvent("oplium")

	// Determine event type based on subject and body content
	if strings.Contains(subjectLower, "dmca") || strings.Contains(strings.ToLower(body), "copyright") {
		event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}
	} else if strings.Contains(subjectLower, "phishing") || strings.Contains(strings.ToLower(body), "phishing") {
		event.EventTypes = []events.EventType{events.NewPhishing()}
	} else {
		return nil, common.NewNewTypeError(subjectLower)
	}

	// Parse event date
	if strings.Contains(body, "GMT-3") {
		dateStr := common.FindStringWithoutMarkers(
			body,
			"One of the accesses to the site occurred on",
			"",
		)
		dateStr = strings.TrimSpace(dateStr)
		if dateStr != "" {
			// Format extracted: "01/15/2024 at 02:30 PM"
			// Add GMT-0300 suffix as per Python logic
			dateStr = dateStr + " GMT-0300"
			// Parse custom date format matching Python's '%m/%d/%Y at %I:%M %p %Z%z'
			// Go format: "01/02/2006 at 03:04 PM MST-0700"
			if t, err := time.Parse("01/02/2006 at 03:04 PM MST-0700", dateStr); err == nil {
				event.EventDate = &t
			} else if t, err := time.Parse("1/2/2006 at 3:04 PM MST-0700", dateStr); err == nil {
				// Try without leading zeros
				event.EventDate = &t
			}
		}
	} else {
		// Use email header date
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Extract IP address
	ip := common.FindStringWithoutMarkers(body, "IP address", "")
	if ip != "" {
		event.IP = ip
	}

	// Extract URL
	url := common.FindStringWithoutMarkers(body, "URL:", "")
	if url == "" {
		url = subjectLower
	}
	if url != "" {
		event.URL = url
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
