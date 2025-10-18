package csirt_cz

import (
	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"regexp"
	"strings"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	bodyLower := strings.ToLower(body)

	var result []*events.Event

	// Simplified implementation - handles basic text format
	// Full implementation would need ZIP attachment parsing, CSV parsing, etc.

	// Check for phishing report
	if strings.Contains(bodyLower, "phishing") || strings.Contains(bodyLower, "fake web page") {
		// Extract IP and date
		ip := common.FindStringWithoutMarkers(bodyLower, "originating at computer ", " which")
		eventDate := common.FindStringWithoutMarkers(bodyLower, "datum: ", "")

		// Try to extract URLs
		urlRe := regexp.MustCompile(`(?m)^(https?://\S+|hxxp://\S+)`)
		urls := urlRe.FindAllString(body, -1)

		if len(urls) == 0 {
			event := events.NewEvent("csirt_cz")
			event.EventTypes = []events.EventType{events.NewPhishing()}
			if eventDate != "" {
			}
			event.IP = common.IsIP(ip)
			result = append(result, event)
		} else {
			for _, url := range urls {
				event := events.NewEvent("csirt_cz")
				phishing := events.NewPhishing()
				phishing.PhishingTarget = url
				event.EventTypes = []events.EventType{phishing}
				if eventDate != "" {
				}
				event.IP = common.IsIP(ip)
				event.URL = url
				result = append(result, event)
			}
		}
	} else if strings.Contains(bodyLower, "spam") {
		ip := common.FindStringWithoutMarkers(bodyLower, "ip address ", "")
		eventDate := common.FindStringWithoutMarkers(bodyLower, "datum: ", "")

		event := events.NewEvent("csirt_cz")
		event.EventTypes = []events.EventType{events.NewSpam()}
		if eventDate != "" {
		}
		event.IP = common.IsIP(ip)
		result = append(result, event)
	} else if strings.Contains(bodyLower, "network abuse") {
		ip := common.FindStringWithoutMarkers(bodyLower, "originating at computer ", "")
		eventDate := common.FindStringWithoutMarkers(bodyLower, "datum: ", "")

		event := events.NewEvent("csirt_cz")
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
		if eventDate != "" {
		}
		event.IP = common.IsIP(ip)
		result = append(result, event)
	} else if strings.Contains(bodyLower, "malware") {
		// Simplified - would need CSV parsing for full implementation
		event := events.NewEvent("csirt_cz")
		event.EventTypes = []events.EventType{events.NewMalware("")}
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		}
		result = append(result, event)
	} else {
		subject, _ := common.GetSubject(serializedEmail, false)
		return nil, common.NewNewTypeError(subject)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
