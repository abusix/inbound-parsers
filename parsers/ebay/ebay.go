// Package ebay implements the ebay parser
package ebay

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the ebay parser
type Parser struct{}

// Parse parses emails for ebay phishing reports
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Extract IP and domain from subject first
	ip := common.ExtractOneIP(subject)
	domain := extractDomainFromEnd(subject)

	// If not found in subject, try body
	if ip == "" || domain == "" {
		lines := strings.Split(body, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if len(line) > 0 {
				if ip == "" {
					ip = common.ExtractOneIP(line)
				}
				if domain == "" {
					domain = extractDomainFromEnd(line)
				}
				if ip != "" && domain != "" {
					break
				}
			}
		}
	}

	// Need both IP and domain
	if ip == "" || domain == "" {
		return []*events.Event{}, nil
	}

	event := events.NewEvent("ebay")
	event.IP = ip
	event.URL = domain
	event.EventTypes = []events.EventType{events.NewPhishing()}

	// Parse event date
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	return []*events.Event{event}, nil
}

// extractDomainFromEnd extracts the last part after space (domain)
func extractDomainFromEnd(text string) string {
	parts := strings.Split(text, " ")
	if len(parts) > 0 {
		lastPart := strings.TrimSpace(parts[len(parts)-1])
		// Basic validation - should contain a dot
		if strings.Contains(lastPart, ".") {
			return lastPart
		}
	}
	return ""
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
