package acedatacenter

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

// extractForwardedMessage extracts the forwarded message from quoted lines (lines starting with '>')
// This matches the Python rewrite() function logic
func extractForwardedMessage(body string, dateHeader string) (string, error) {
	lines := strings.Split(body, "\n")
	var forwardedLines []string

	for _, line := range lines {
		// Skip the "forwarded message:" line but include other quoted lines
		if strings.HasPrefix(line, ">") {
			if !strings.Contains(strings.ToLower(line), "forwarded message:") {
				// Remove the '>' and any leading whitespace/BOM
				unquoted := strings.TrimLeft(line[1:], " \ufeff")
				forwardedLines = append(forwardedLines, unquoted)
			}
		}
	}

	// Skip initial blank line if present
	if len(forwardedLines) > 0 && strings.TrimSpace(forwardedLines[0]) == "" {
		forwardedLines = forwardedLines[1:]
	}

	// Replace the Date header with the forwarder's date (as unstable format in forwarded message)
	if dateHeader != "" {
		for i, line := range forwardedLines {
			if strings.HasPrefix(line, "Date:") {
				forwardedLines[i] = "Date: " + dateHeader
				break
			}
		}
	}

	forwardedMail := strings.Join(forwardedLines, "\n")
	if strings.TrimSpace(forwardedMail) == "" {
		return "", common.NewParserError("No forwarded message found")
	}

	return forwardedMail, nil
}

// parseXARFContent extracts basic XARF information from the forwarded message
// This is a simplified version since full XARF parsing is complex
func parseXARFContent(forwardedBody string, subject string, date string) (*events.Event, error) {
	event := events.NewEvent("acedatacenter")

	// Set date
	if date != "" {
		event.EventDate = email.ParseDate(date)
	}

	// Look for XARF version marker to validate it's XARF
	if !strings.Contains(forwardedBody, "Version: 0.2") {
		return nil, common.NewParserError("XARF version marker not found")
	}

	// Extract YAML-like XARF data block around Version: 0.2
	xarfLines := common.GetBlockAround(forwardedBody, "Version: 0.2")

	// Try to extract basic fields from XARF format
	var reportType, sourceIP, reportedURL string

	for _, line := range xarfLines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Attachment:") {
			break // Stop at attachment marker
		}

		// Parse YAML-like key-value pairs
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				switch key {
				case "Report-Type":
					reportType = value
				case "Source-IP", "Source-Ip", "Source":
					sourceIP = value
				case "Reported-Uri", "Reported-URL":
					reportedURL = value
				}
			}
		}
	}

	// Set IP if found
	if sourceIP != "" {
		event.IP = sourceIP
	}

	// Set URL if found
	if reportedURL != "" {
		event.URL = reportedURL
	}

	// Determine event type based on Report-Type
	switch strings.ToLower(reportType) {
	case "abuse":
		event.EventTypes = []events.EventType{events.NewSpam()}
	case "fraud":
		event.EventTypes = []events.EventType{events.NewPhishing()}
	case "login-attack":
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	default:
		// Default to spam if type unclear
		event.EventTypes = []events.EventType{events.NewSpam()}
	}

	return event, nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)

	// Check if this is a XARF-style report
	if !strings.Contains(body, "X-ARF") {
		return nil, common.NewParserError("Not an X-ARF report")
	}

	// Get date header for fallback
	var dateHeader string
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateHeader = dateHeaders[0]
	}

	// Extract forwarded message from quoted lines
	forwardedMail, err := extractForwardedMessage(body, dateHeader)
	if err != nil {
		return nil, err
	}

	// Get subject from forwarded message or use original
	subject, _ := common.GetSubject(serializedEmail, false)

	// Parse XARF content from forwarded message
	event, err := parseXARFContent(forwardedMail, subject, dateHeader)
	if err != nil {
		return nil, err
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
