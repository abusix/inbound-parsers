// Package telecentras implements the telecentras.lt parser
package telecentras

import (
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the telecentras.lt parser
type Parser struct{}

// NewParser creates a new telecentras parser
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from @telecentras.lt
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	// Reject replies
	if strings.Contains(subjectLower, "re:") {
		return nil, common.NewRejectError("reply email")
	}

	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Handle forwarded emails
	if strings.Contains(subjectLower, "fw:") && strings.Contains(body, "-----Original Message-----") {
		if err := rewriteForwardedEmail(serializedEmail, body); err != nil {
			return nil, err
		}
		// Re-get body after rewrite
		body, err = common.GetBody(serializedEmail, true)
		if err != nil {
			return nil, err
		}
	}

	// Remove carriage returns and trim
	body = strings.ReplaceAll(body, "\r", "")
	body = strings.TrimSpace(body)

	if strings.Contains(subjectLower, "ddos attack") {
		return parseDDoS(serializedEmail, body)
	}

	return nil, common.NewNewTypeError(subject)
}

// rewriteForwardedEmail extracts the original message from a forwarded email
func rewriteForwardedEmail(serializedEmail *email.SerializedEmail, body string) error {
	marker := "-----Original Message-----"

	// Add newline after marker for consistent parsing
	body = strings.ReplaceAll(body, marker, marker+"\n")

	// Extract header lines after the marker
	headerLines := common.GetBlockAfterWithStop(body, marker, "")
	if len(headerLines) == 0 {
		return common.NewParserError("no header lines found in forwarded message")
	}

	// Find where the headers end (last header line)
	lastHeaderLine := headerLines[len(headerLines)-1]

	// Split body to get the actual message content
	parts := strings.SplitN(body, lastHeaderLine, 2)
	if len(parts) != 2 {
		return common.NewParserError("could not split forwarded message")
	}

	// Build new headers from the forwarded message
	newHeaders := buildHeadersFromLines(headerLines, serializedEmail)

	// Update the serialized email
	serializedEmail.Body = parts[1]
	serializedEmail.Headers = newHeaders

	return nil
}

// buildHeadersFromLines parses header lines and creates a header map
func buildHeadersFromLines(headerLines []string, originalEmail *email.SerializedEmail) map[string][]string {
	headers := make(map[string][]string)

	for _, line := range headerLines {
		// Split on first ": "
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.ToLower(parts[0])
		value := parts[1]

		// Special handling for "Sent" field -> becomes "date"
		if key == "sent" {
			// Try to parse with custom format: "Tuesday, September 13, 2022 2:53 AM"
			formats := []string{"%A, %B %d, %Y %I:%M %p"}
			if parsedDate := ParseForwardedDate(value, formats); parsedDate != nil {
				headers["date"] = []string{parsedDate.Format(time.RFC1123Z)}
			} else {
				// Fallback to original date
				if origDate, ok := originalEmail.Headers["date"]; ok {
					headers["date"] = origDate
				}
			}
			continue
		}

		headers[key] = []string{value}
	}

	return headers
}

func parseDDoS(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	event := events.NewEvent("telecentras")
	event.EventTypes = []events.EventType{events.NewDDoS()}

	// Get event date from headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Try to extract IP address from body
	// Pattern: "IP addresses: <ip>," or similar
	ip := common.FindStringWithoutMarkers(body, "IP addresses: ", ",")
	if ip != "" {
		// Validate it's an IP
		if validIP := common.IsIP(ip); validIP != "" {
			event.IP = validIP
		}
	}

	// Only yield event if we found an IP
	if event.IP != "" {
		return []*events.Event{event}, nil
	}

	// No IP found, return empty result
	return []*events.Event{}, nil
}

// ParseForwardedDate parses a date with custom format
// Supports format: "Tuesday, September 13, 2022 2:53 AM"
func ParseForwardedDate(dateStr string, formats []string) *time.Time {
	dateStr = strings.TrimSpace(dateStr)
	if dateStr == "" {
		return nil
	}

	// Try each format
	for _, format := range formats {
		// Convert Python strftime format to Go time format
		goFormat := convertPythonDateFormat(format)
		if t, err := time.Parse(goFormat, dateStr); err == nil {
			return &t
		}
	}

	return nil
}

// convertPythonDateFormat converts Python strftime format to Go time format
// %A = Monday, %B = January, %d = 02, %Y = 2006, %I = 03, %M = 04, %p = PM
func convertPythonDateFormat(pythonFormat string) string {
	goFormat := pythonFormat
	goFormat = strings.ReplaceAll(goFormat, "%A", "Monday")
	goFormat = strings.ReplaceAll(goFormat, "%B", "January")
	goFormat = strings.ReplaceAll(goFormat, "%d", "02")
	goFormat = strings.ReplaceAll(goFormat, "%Y", "2006")
	goFormat = strings.ReplaceAll(goFormat, "%I", "03")
	goFormat = strings.ReplaceAll(goFormat, "%M", "04")
	goFormat = strings.ReplaceAll(goFormat, "%p", "PM")
	return goFormat
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
