package generic_spam_trap

import (
	"encoding/base64"
	"strings"

	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	event := events.NewEvent("generic_spam_trap")

	// Create spam event type with "trap" subtype
	spam := events.NewSpam()
	event.EventTypes = []events.EventType{spam}

	// Extract IP from X-Originating-IP header or Received header
	if originIP, ok := serializedEmail.Headers["x-originating-ip"]; ok && len(originIP) > 0 {
		if validIP := common.IsIP(originIP[0]); validIP != "" {
			event.IP = validIP
		}
	}

	// Fallback: extract from first Received header
	if event.IP == "" {
		if received, ok := serializedEmail.Headers["received"]; ok && len(received) > 0 {
			// Extract IP from Received header (look for [IP] pattern)
			ip := common.ExtractOneIP(received[0])
			if ip != "" {
				event.IP = ip
			}
		}
	}

	// Extract sender email from From header
	if from, ok := serializedEmail.Headers["from"]; ok && len(from) > 0 {
		fromAddr := extractEmailFromHeader(from[0])
		if fromAddr != "" {
			// Add email event detail
			emailDetail := &events.Email{
				FromAddress: fromAddr,
			}
			event.AddEventDetail(emailDetail)
		}
	}

	// Extract recipient email from To header
	if to, ok := serializedEmail.Headers["to"]; ok && len(to) > 0 {
		event.RecipientEmail = extractEmailFromHeader(to[0])
	}

	// Extract dates
	// Send date from Date header
	if date, ok := serializedEmail.Headers["date"]; ok && len(date) > 0 {
		if parsedDate := email.ParseDate(date[0]); parsedDate != nil {
			event.SendDate = parsedDate
			event.EventDate = parsedDate
		}
	}

	// Received date from first Received header
	if received, ok := serializedEmail.Headers["received"]; ok && len(received) > 0 {
		// Extract date from Received header (after semicolon)
		receivedHeader := received[0]
		if idx := strings.LastIndex(receivedHeader, ";"); idx != -1 {
			dateStr := strings.TrimSpace(receivedHeader[idx+1:])
			if parsedDate := email.ParseDate(dateStr); parsedDate != nil {
				event.ReceivedDate = parsedDate
			}
		}
	}

	// Create sample event detail with the original email
	sample := &events.Sample{
		ContentType: "message/rfc822",
		Encoding:    "base64",
		Description: "Redacted headers",
		Payload:     createRedactedEmailPayload(serializedEmail),
	}
	event.AddEventDetail(sample)

	return []*events.Event{event}, nil
}

// extractEmailFromHeader extracts email address from a header value like "Name <email@domain.com>"
func extractEmailFromHeader(header string) string {
	// Look for <email> pattern
	start := strings.Index(header, "<")
	end := strings.Index(header, ">")

	if start != -1 && end != -1 && end > start {
		return header[start+1 : end]
	}

	// If no angle brackets, return the trimmed header
	return strings.TrimSpace(header)
}

// createRedactedEmailPayload creates a base64-encoded redacted version of the email
func createRedactedEmailPayload(serializedEmail *email.SerializedEmail) string {
	var redacted strings.Builder

	// Include select headers
	includeHeaders := []string{
		"authentication-results",
		"received-spf",
		"received",
		"x-originating-ip",
		"dkim-signature",
		"date",
		"subject",
		"message-id",
		"from",
		"content-transfer-encoding",
		"content-type",
	}

	for _, headerName := range includeHeaders {
		headerKey := strings.ToLower(headerName)
		if values, ok := serializedEmail.Headers[headerKey]; ok {
			for _, value := range values {
				// Redact sensitive parts but keep structure
				redactedValue := redactHeaderValue(headerKey, value)
				redacted.WriteString(headerName)
				redacted.WriteString(": ")
				redacted.WriteString(redactedValue)
				redacted.WriteString("\r\n")
			}
		}
	}

	// Add redacted body
	redacted.WriteString("\r\n")
	redacted.WriteString("BODY REDACTED\r\n")

	// Encode as base64
	return base64.StdEncoding.EncodeToString([]byte(redacted.String()))
}

// redactHeaderValue redacts sensitive information in header values
func redactHeaderValue(headerName, value string) string {
	switch headerName {
	case "received":
		// Redact server names but keep IPs visible
		value = strings.ReplaceAll(value, "vimdzmsp-mxin04.bluewin.ch", "<REDACTED>")
		value = strings.ReplaceAll(value, "smtp-forward.abusix.com", "<REDACTED>")
		// Look for "id <ID>" patterns and redact
		if idx := strings.Index(value, "id "); idx != -1 {
			after := value[idx+3:]
			if endIdx := strings.IndexAny(after, "; \r\n"); endIdx != -1 {
				value = value[:idx+3] + "<REDACTED>" + after[endIdx:]
			}
		}
	case "date":
		// Redact time details but keep date structure
		if idx := strings.Index(value, ":"); idx != -1 {
			// Find the last number before timezone
			parts := strings.Fields(value)
			for i, part := range parts {
				if strings.Contains(part, ":") {
					parts[i] = "<REDACTED>"
				}
			}
			value = strings.Join(parts, " ")
		}
	case "message-id":
		// Redact message ID content
		if start := strings.Index(value, "<"); start != -1 {
			if end := strings.Index(value, "@"); end != -1 && end > start {
				value = value[:start+1] + "<REDACTED>" + value[end:]
			}
		}
	case "dkim-signature":
		// Redact signature values
		if idx := strings.Index(value, "bh="); idx != -1 {
			after := value[idx+3:]
			if endIdx := strings.IndexAny(after, ";"); endIdx != -1 {
				value = value[:idx+3] + "<REDACTED>" + after[endIdx:]
			}
		}
		if idx := strings.Index(value, "\n\tb="); idx != -1 {
			value = value[:idx] + "\n\tb=<REDACTED>"
		} else if idx := strings.Index(value, "b="); idx != -1 {
			value = value[:idx] + "b=<REDACTED>"
		}
	}
	return value
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 1000
}
