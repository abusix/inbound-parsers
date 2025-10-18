// Package marf implements the MARF (Messaging Abuse Reporting Format) parser
// MARF is defined in RFC 5965 and is also known as ARF (Abuse Reporting Format)
package marf

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// Parse parses a MARF/ARF formatted email
// MARF emails are multipart with:
// - Part 0: Human-readable message
// - Part 1: Machine-readable report (message/feedback-report)
// - Part 2: Original message (message/rfc822 or text/rfc822-headers)
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// MARF requires at least 3 parts
	if len(serializedEmail.Parts) < 3 {
		return nil, common.NewParserError("MARF format requires at least 3 parts")
	}

	// Get the machine-readable report (part 1)
	reportPart := serializedEmail.Parts[1]
	if reportPart.Headers == nil {
		return nil, common.NewParserError("report part has no headers")
	}

	// Extract report body
	var reportBody string
	switch body := reportPart.Body.(type) {
	case string:
		reportBody = body
	case []byte:
		reportBody = string(body)
	default:
		return nil, common.NewParserError("unexpected report body type")
	}

	// Parse report as key-value pairs
	reportData := parseReportBody(reportBody)

	// Get the original message part (part 2)
	messagePart := serializedEmail.Parts[2]

	event := events.NewEvent("marf")

	// Parse Feedback-Type to determine event type
	feedbackType := getReportField(reportData, reportPart.Headers, "feedback-type")
	switch strings.ToLower(feedbackType) {
	case "abuse":
		event.EventTypes = []events.EventType{events.NewSpam()}
	case "fraud":
		event.EventTypes = []events.EventType{events.NewPhishing()}
	case "virus":
		event.EventTypes = []events.EventType{events.NewMalware("")}
	case "not-spam":
		event.EventTypes = []events.EventType{events.NewSpam()} // Still track it as spam-related
	default:
		// Default to spam for other types
		event.EventTypes = []events.EventType{events.NewSpam()}
	}

	// Extract Source-IP
	sourceIP := getReportField(reportData, reportPart.Headers, "source-ip")
	if sourceIP != "" {
		if validIP := common.IsIP(sourceIP); validIP != "" {
			event.IP = validIP
		}
	}

	// Extract Source-Port
	sourcePort := getReportField(reportData, reportPart.Headers, "source-port")
	if sourcePort != "" {
		if port, err := strconv.Atoi(strings.TrimSpace(sourcePort)); err == nil {
			event.Port = port
		}
	}

	// Extract User-Agent
	userAgent := getReportField(reportData, reportPart.Headers, "user-agent")
	if userAgent != "" {
		if event.Headers == nil {
			event.Headers = make(map[string]interface{})
		}
		event.Headers["user-agent"] = []string{userAgent}
	}

	// Extract Version
	version := getReportField(reportData, reportPart.Headers, "version")
	if version != "" {
		if event.Headers == nil {
			event.Headers = make(map[string]interface{})
		}
		event.Headers["arf-version"] = []string{version}
	}

	// Extract Reported-Domain
	reportedDomain := getReportField(reportData, reportPart.Headers, "reported-domain")
	if reportedDomain != "" {
		event.URL = reportedDomain
	}

	// Extract Reported-URI
	reportedURI := getReportField(reportData, reportPart.Headers, "reported-uri")
	if reportedURI != "" {
		// Reported-URI takes precedence over Reported-Domain
		event.URL = reportedURI
	}

	// Try to extract URL from original message if not already set
	if event.URL == "" {
		var messageBody string
		if messagePart.Body != nil {
			switch body := messagePart.Body.(type) {
			case string:
				messageBody = body
			case []byte:
				messageBody = string(body)
			}
		}

		// Extract URLs from message body
		if messageBody != "" {
			urlRegex := regexp.MustCompile(`https?://[^\s<>"{}|\\^[\]` + "`" + `]+`)
			if matches := urlRegex.FindStringSubmatch(messageBody); len(matches) > 0 {
				event.URL = matches[0]
			}
		}
	}

	// Extract Arrival-Date for event timestamp
	arrivalDate := getReportField(reportData, reportPart.Headers, "arrival-date")
	if arrivalDate != "" {
		event.EventDate = email.ParseDate(arrivalDate)
	}

	// If no arrival date, use the email's Date header
	if event.EventDate == nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Extract Original-Mail-From
	originalMailFrom := getReportField(reportData, reportPart.Headers, "original-mail-from")
	if originalMailFrom != "" {
		if event.Headers == nil {
			event.Headers = make(map[string]interface{})
		}
		event.Headers["original-mail-from"] = []string{originalMailFrom}
	}

	// Extract Original-Rcpt-To
	originalRcptTo := getReportField(reportData, reportPart.Headers, "original-rcpt-to")
	if originalRcptTo != "" {
		if event.Headers == nil {
			event.Headers = make(map[string]interface{})
		}
		event.Headers["original-rcpt-to"] = []string{originalRcptTo}
	}

	// Store feedback type
	if feedbackType != "" {
		if event.Headers == nil {
			event.Headers = make(map[string]interface{})
		}
		event.Headers["feedback-type"] = []string{feedbackType}
	}

	// Extract Authentication-Results from report if available
	authResults := getReportField(reportData, reportPart.Headers, "authentication-results")
	if authResults != "" {
		if event.Headers == nil {
			event.Headers = make(map[string]interface{})
		}
		event.Headers["authentication-results"] = []string{authResults}
	}

	// Extract Incidents count if present
	incidents := getReportField(reportData, reportPart.Headers, "incidents")
	if incidents != "" {
		if event.Headers == nil {
			event.Headers = make(map[string]interface{})
		}
		event.Headers["incidents"] = []string{incidents}
	}

	return []*events.Event{event}, nil
}

// parseReportBody parses the machine-readable report body into key-value pairs
func parseReportBody(body string) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(body, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse "Key: Value" format
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.ToLower(strings.TrimSpace(parts[0]))
			value := strings.TrimSpace(parts[1])
			result[key] = value
		}
	}

	return result
}

// getReportField tries to get a field from parsed body first, then from headers
func getReportField(reportData map[string]string, headers map[string][]string, fieldName string) string {
	fieldNameLower := strings.ToLower(fieldName)

	// Try parsed body first
	if val, ok := reportData[fieldNameLower]; ok && val != "" {
		return val
	}

	// Try headers
	if headers != nil {
		if vals, ok := headers[fieldNameLower]; ok && len(vals) > 0 {
			return vals[0]
		}
	}

	return ""
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 10
}
