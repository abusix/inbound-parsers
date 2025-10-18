// Package ibcom implements the ibcom (Group-IB) parser
package ibcom

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the ibcom parser
type Parser struct{}

var (
	urlPattern = regexp.MustCompile(`(?i)(?P<url>(hxxp|http)\S+)`)
)

// Parse parses emails from drp-response@group-ib.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)

	// Get event date from headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	var result []*events.Event

	// Check for trademark
	if strings.Contains(bodyLower, "trademark") {
		event := events.NewEvent("ibcom")
		event.EventDate = eventDate
		event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}

		// Extract IP
		ip := common.FindStringWithoutMarkers(bodyLower, "(ip", ")")
		if ip != "" {
			event.IP = ip
		}

		// Extract URL
		if match := urlPattern.FindStringSubmatch(body); len(match) > 1 {
			event.URL = match[1]
		}

		// Only yield if we have IP or URL
		if event.IP != "" || event.URL != "" {
			result = append(result, event)
		}
	} else if strings.Contains(bodyLower, "copyright") ||
		strings.Contains(subjectLower, "unauthorised distribution") ||
		strings.Contains(subjectLower, "copyright") {
		// Copyright event
		event := events.NewEvent("ibcom")
		event.EventDate = eventDate
		event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}

		// Try to get URL after "page:"
		url := common.GetNonEmptyLineAfter(body, "page:")
		if url != "" {
			event.URL = url
			result = append(result, event)
		} else if match := urlPattern.FindStringSubmatch(body); len(match) > 1 {
			// Try regex pattern
			event.URL = match[1]
			result = append(result, event)
		}
	} else if strings.Contains(bodyLower, "phishing") ||
		strings.Contains(bodyLower, "websites are luring") ||
		strings.Contains(subjectLower, "phishing") {
		// Phishing event
		event := events.NewEvent("ibcom")
		event.EventDate = eventDate
		event.EventTypes = []events.EventType{events.NewPhishing()}

		// Fix typo in body: Domian -> Domain
		bodyFixed := strings.ReplaceAll(body, "Domian", "Domain")

		// Try to extract URL from "Domain:" marker
		url := common.FindStringWithoutMarkers(bodyFixed, "Domain:", "")
		if url != "" {
			event.URL = url
		}

		// Try regex pattern
		if match := urlPattern.FindStringSubmatch(body); len(match) > 1 {
			event.URL = match[1]
			result = append(result, event)
		} else {
			// Try "The URL:" marker
			url = common.GetNonEmptyLineAfter(body, "The URL:")
			if url != "" {
				event.URL = url
			}
		}

		// Extract IP
		ip := common.FindStringWithoutMarkers(bodyLower, "ip:", "")
		if ip != "" {
			event.IP = ip
		}

		result = append(result, event)
	} else if strings.Contains(subjectLower, "fraudulent") {
		// Fraud event
		event := events.NewEvent("ibcom")
		event.EventDate = eventDate
		event.EventTypes = []events.EventType{events.NewFraud()}

		// Try simple URL pattern first
		if match := urlPattern.FindStringSubmatch(body); len(match) > 1 {
			event.URL = match[1]
			result = append(result, event)
		} else {
			// Try combined pattern with IP
			combinedPattern := regexp.MustCompile(`(?i)(?P<url>http\S+) (?P<ip>(\d|\.)+)`)
			if match := combinedPattern.FindStringSubmatch(body); len(match) > 2 {
				event.URL = match[1]
				event.IP = match[3]
				result = append(result, event)
			}
		}
	} else {
		// Unknown type
		return nil, common.NewNewTypeError(subject)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
