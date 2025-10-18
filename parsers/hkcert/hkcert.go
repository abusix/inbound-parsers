package hkcert

import (
	"strings"

	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	event := events.NewEvent("hkcert")

	// Parse event date from headers
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Get body and subject as lowercase
	body, _ := common.GetBody(serializedEmail, false)
	bodyLower := strings.ToLower(body)

	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	// Extract external ID from subject (between "hkcert" and "-")
	externalID := common.FindStringWithoutMarkers(subjectLower, "hkcert", "-")
	externalID = strings.TrimSpace(externalID)
	if externalID != "" {
		event.AddEventDetail(&events.ExternalID{ID: externalID})
	}

	// Determine event type based on body and subject
	eventType := common.FindStringWithoutMarkers(bodyLower, "type: ", "")

	if strings.Contains(eventType, "bot") || strings.Contains(subjectLower, "bot") {
		event.EventTypes = []events.EventType{events.NewBot("")}
	} else if strings.Contains(eventType, "phishing") || strings.Contains(subjectLower, "phishing") {
		event.EventTypes = []events.EventType{events.NewPhishing()}
	} else if strings.Contains(eventType, "malware") || strings.Contains(eventType, "information leakage") || strings.Contains(subjectLower, "malware") {
		event.EventTypes = []events.EventType{events.NewMalware("")}
	} else if strings.Contains(eventType, "vulnerable system") || strings.Contains(subjectLower, "vulnerable system") {
		if strings.Contains(bodyLower, "cve-") {
			cveName := "cve-" + common.FindStringWithoutMarkers(bodyLower, "cve-", " ")
			event.EventTypes = []events.EventType{events.NewCVE(cveName, "", "")}
		} else if strings.Contains(bodyLower, "web shell") {
			event.EventTypes = []events.EventType{events.NewBackdoor()}
		}
	} else {
		// If we can't determine the type, return an error
		return nil, &common.NewTypeError{Subject: eventType}
	}

	// Extract IP address
	ip := common.FindStringWithoutMarkers(bodyLower, "ip:", "")
	if ip != "" {
		event.IP = common.ExtractOneIP(ip)
	}

	// If no IP found, try alternative extraction methods
	if event.IP == "" {
		if strings.Contains(bodyLower, "details:") {
			parts := strings.Split(bodyLower, "details:")
			if len(parts) > 1 {
				details := parts[len(parts)-1]
				event.IP = common.ExtractOneIP(details)
				// Also set URL with cleaned details
				event.URL = strings.ReplaceAll(strings.TrimSpace(details), "[.]", ".")
			}
		} else if attachment, err := common.FindFirstAttachmentWithMimeType(serializedEmail, ".xls"); err == nil {
			// If there's an .xls attachment, set it as IP (for further processing)
			event.IP = common.ExtractOneIP(attachment)
		} else if strings.Contains(bodyLower, "the following website") || strings.Contains(bodyLower, "the following url") {
			// Replace "the following website" with "the following url" for consistent parsing
			bodyForURL := strings.ReplaceAll(bodyLower, "the following website", "the following url")
			url := common.GetNonEmptyLineAfter(bodyForURL, "the following url")
			if url != "" {
				event.URL = strings.ReplaceAll(url, "[.]", ".")
			}
		} else {
			// Last resort: try to extract IP from entire body
			event.IP = common.ExtractOneIP(bodyLower)
		}
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
