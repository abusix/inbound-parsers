package doppel

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
	// Get body and subject
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("no email body found")
	}

	subject, _ := common.GetSubject(serializedEmail, false)

	// Create base event
	event := events.NewEvent("doppel")

	// Get event date from headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		event.EventDate = email.ParseDate(dateHeader[0])
	}

	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)

	// Determine event type and extract data
	if strings.Contains(body, "phishing") {
		// Phishing event
		if officialURL := common.FindStringWithoutMarkers(body, "Original Site:", ""); officialURL != "" {
			event.EventTypes = []events.EventType{events.NewPhishingWithOfficialURL(strings.TrimSpace(officialURL))}
		} else {
			event.EventTypes = []events.EventType{events.NewPhishing()}
		}

		// Extract URL - try multiple markers
		var url string
		if url = common.FindStringWithoutMarkers(body, "Phishing Site:", ""); url != "" {
			event.URL = strings.TrimSpace(url)
		} else if url = common.FindStringWithoutMarkers(body, "Phishing Link(s):", ""); url != "" {
			event.URL = strings.TrimSpace(url)
		} else if url = common.FindStringWithoutMarkers(body, "Phishing Site(s):", ""); url != "" {
			event.URL = strings.TrimSpace(url)
		} else if url = common.FindStringWithoutMarkers(body, "Reporting Link:", ""); url != "" {
			event.URL = strings.TrimSpace(url)
		} else if url = common.GetNonEmptyLineAfter(body, "Malicious URL(s)"); url != "" {
			event.URL = strings.TrimSpace(url)
		}

		// Extract IP address
		if ip := common.FindStringWithoutMarkers(bodyLower, "ip address:", ""); ip != "" {
			event.IP = ip
		}

		return []*events.Event{event}, nil

	} else if strings.Contains(body, "trademark") {
		// Trademark event
		event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}

		if url := common.FindStringWithoutMarkers(body, "Infringing Site:", ""); url != "" {
			event.URL = strings.TrimSpace(url)
		}

		return []*events.Event{event}, nil

	} else if strings.Contains(subjectLower, "copyright") {
		// Copyright event
		event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}

		// Try to extract URL
		var url string
		if url = common.GetNonEmptyLineAfter(body, "infringing materials are located at:"); url != "" {
			event.URL = url
		} else if url = common.GetNonEmptyLineAfter(body, "infringing material is located at:"); url != "" {
			event.URL = url
		}

		return []*events.Event{event}, nil

	} else if strings.Contains(body, "malicious content") {
		// Malicious activity event
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}

		if url := common.FindStringWithoutMarkers(body, "hosted on this site:", ""); url != "" {
			event.URL = url
		}

		if ip := common.FindStringWithoutMarkers(body, "IP Address:", ""); ip != "" {
			event.IP = ip
		}

		return []*events.Event{event}, nil

	} else {
		// Unknown type
		return nil, common.NewNewTypeError(subjectLower)
	}
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
