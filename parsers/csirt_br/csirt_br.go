package csirt_br

import (
	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"strings"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	var result []*events.Event
	eventTemplate := events.NewEvent("csirt_br")

	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
	}

	if strings.Contains(body, "malicious activity") {
		eventTemplate.EventTypes = []events.EventType{events.NewMaliciousActivity()}

		if strings.Contains(subjectLower, "multiple ip addresses") {
			// Check for attachment with IPs
			attachment, err := common.FindFirstAttachmentWithMimeType(serializedEmail, ".txt")
			if err == nil && attachment != "" {
				lines := strings.Split(attachment, "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line != "" {
						if ip := common.IsIP(line); ip != "" {
							event := events.NewEvent("csirt_br")
							event.EventTypes = eventTemplate.EventTypes
							event.EventDate = eventTemplate.EventDate
							event.IP = ip
							result = append(result, event)
						}
					}
				}
			} else {
				// Try to extract from body
				ipsString := common.FindStringWithoutMarkers(strings.ReplaceAll(body, ";", ":"), "List of attached IPs:", "4. We request")
				lines := strings.Split(ipsString, "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line != "" {
						if ip := common.IsIP(line); ip != "" {
							event := events.NewEvent("csirt_br")
							event.EventTypes = eventTemplate.EventTypes
							event.EventDate = eventTemplate.EventDate
							event.IP = ip
							result = append(result, event)
						}
					}
				}
			}
		} else {
			// Single IP
			if ip := common.IsIP(subjectLower); ip != "" {
				eventTemplate.IP = ip
			} else {
				ip := common.FindStringWithoutMarkers(body, "Source IP´s address", "")
				eventTemplate.IP = common.IsIP(ip)
			}
			result = append(result, eventTemplate)
		}
	} else if strings.Contains(subjectLower, "phishing") {
		eventTemplate.EventTypes = []events.EventType{events.NewPhishing()}
		url := common.FindStringWithoutMarkers(body, "following website recently came to my attention:", "")
		eventTemplate.URL = url
		result = append(result, eventTemplate)
	} else {
		return nil, common.NewNewTypeError(subjectLower)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
