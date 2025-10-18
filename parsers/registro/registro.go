package registro

import (
	"fmt"
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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	body = strings.ReplaceAll(body, "  ", " ")

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)
	bodyLower := strings.ToLower(body)

	// Check if this is an abuse report with phishing
	if strings.Contains(subjectLower, "abuse report") && strings.Contains(body, "phishing") {
		return parsePhishing(
			serializedEmail,
			subject,
			body,
			"#(HEADER)#",
			"following e-mail server:",
			"This fake message",
		)
	}

	// Check if this is a Portuguese notification
	if strings.Contains(subjectLower, "notificação de incidente") &&
		(strings.Contains(bodyLower, "mensagens de fraudes") || strings.Contains(bodyLower, "phishing")) {
		return parsePhishing(
			serializedEmail,
			subject,
			body,
			"#(CABEï¿½ALHO)#",
			"e-mail sob sua responsabilidade:",
			"Vocï",
		)
	}

	return nil, fmt.Errorf("new type: %s", subject)
}

func parsePhishing(
	serializedEmail *email.SerializedEmail,
	subject, body, attachmentMarker, infoBlockStart, infoBlockEnd string,
) ([]*events.Event, error) {
	eventTemplate := events.NewEvent("registro")
	eventTemplate.EventTypes = []events.EventType{events.NewPhishing()}

	// Try to extract event date from attached mail
	if strings.Contains(body, attachmentMarker) {
		parts := strings.Split(body, attachmentMarker)
		if len(parts) > 1 {
			attachedMail := parts[1]
			lastReceivedHeader := common.FindStringWithoutMarkers(attachedMail, "Received:", "Received")
			if lastReceivedHeader != "" {
				dateParts := strings.Split(lastReceivedHeader, ";")
				if len(dateParts) > 0 {
					dateStr := strings.TrimSpace(dateParts[len(dateParts)-1])
					eventTemplate.EventDate = email.ParseDate(dateStr)
				}
			}
		}
	}

	// Fall back to email date header if no event date found
	if eventTemplate.EventDate == nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventTemplate.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Extract information block
	infoBlock := strings.ToLower(common.FindStringWithoutMarkers(body, infoBlockStart, infoBlockEnd))

	// Extract sender email if present
	if strings.Contains(infoBlock, "authenticated sender") {
		sender := common.FindStringWithoutMarkers(infoBlock, "sender:", "")
		sender = strings.ReplaceAll(sender, " ", "")
		sender = strings.TrimSpace(sender)
		if sender != "" {
			eventTemplate.AddEventDetail(&events.Email{
				FromAddress: sender,
			})
		}
	}

	// Extract URL if present
	if strings.Contains(infoBlock, "url") {
		url := common.FindStringWithoutMarkers(infoBlock, "url:", "")
		url = strings.ReplaceAll(url, " ", "")
		url = strings.TrimSpace(url)
		if url != "" {
			eventTemplate.URL = url
		}
	}

	var result []*events.Event
	ipFound := false

	// Extract IP addresses
	if strings.Contains(infoBlock, "ip:") {
		// IP is before the authenticated sender IP so this will find the mail server IP
		event := copyEvent(eventTemplate)
		ip := common.FindStringWithoutMarkers(infoBlock, "ip:", "")
		ip = strings.ReplaceAll(ip, " ", "")
		ip = strings.TrimSpace(ip)
		if ip != "" {
			event.IP = ip
			ipFound = true
			result = append(result, event)
		}
	}

	if strings.Contains(infoBlock, "authenticated sender ip:") {
		event := copyEvent(eventTemplate)
		ip := common.FindStringWithoutMarkers(infoBlock, "authenticated sender ip:", "")
		ip = strings.ReplaceAll(ip, " ", "")
		ip = strings.TrimSpace(ip)
		if ip != "" {
			event.IP = ip
			ipFound = true
			result = append(result, event)
		}
	}

	// If no IP found, try to extract from subject
	if !ipFound {
		cleanedSubject := subject
		cleanedSubject = strings.TrimPrefix(cleanedSubject, "Abuse report -")
		cleanedSubject = strings.TrimPrefix(cleanedSubject, "Notificação de Incidente -")
		cleanedSubject = strings.ReplaceAll(cleanedSubject, " ", "")
		cleanedSubject = strings.TrimSpace(cleanedSubject)

		if validIP := common.IsIP(cleanedSubject); validIP != "" {
			eventTemplate.IP = validIP
		} else {
			eventTemplate.URL = cleanedSubject
		}
		result = append(result, eventTemplate)
	}

	return result, nil
}

// copyEvent creates a deep copy of an event
func copyEvent(event *events.Event) *events.Event {
	newEvent := events.NewEvent(event.Parser)
	newEvent.IP = event.IP
	newEvent.URL = event.URL
	newEvent.Port = event.Port
	newEvent.Domain = event.Domain
	newEvent.ReportID = event.ReportID
	newEvent.EventTypes = append([]events.EventType{}, event.EventTypes...)
	newEvent.EventDate = event.EventDate
	newEvent.SendDate = event.SendDate
	newEvent.ReceivedDate = event.ReceivedDate
	newEvent.SenderEmail = event.SenderEmail
	newEvent.RecipientEmail = event.RecipientEmail

	// Copy event details
	for _, detail := range event.EventDetails {
		newEvent.EventDetails = append(newEvent.EventDetails, detail)
	}

	// Copy headers
	for k, v := range event.Headers {
		newEvent.Headers[k] = v
	}

	// Copy requirements
	for k, v := range event.Requirements {
		newEvent.Requirements[k] = v
	}

	return newEvent
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
