package amasha

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// getRelevantHeaders extracts Authentication-Results headers from the body
func getRelevantHeaders(body string) []string {
	// Find the end of the headers section
	endIndex := strings.Index(strings.ToLower(body), "content-type: multipart/alternative")
	if endIndex != -1 {
		body = body[:endIndex]
	}

	// Add markers before Authentication-Results lines
	lines := strings.Split(body, "\n")
	var markedLines []string
	for _, line := range lines {
		if strings.HasPrefix(line, "Authentication-Results:") {
			markedLines = append(markedLines, "\nRELEVANT_MARKER\n"+line)
		} else {
			markedLines = append(markedLines, line)
		}
	}

	newBody := strings.Join(markedLines, "\n")

	// Split by marker and filter for Authentication-Results
	parts := strings.Split(newBody, "\nRELEVANT_MARKER\n")
	var received []string
	for _, part := range parts {
		if strings.Contains(part, "Authentication-Results:") {
			received = append(received, part)
		}
	}

	return received
}

// getPartWithAttachment finds the part with message/rfc822 content type
func getPartWithAttachment(serializedEmail *email.SerializedEmail) *email.EmailPart {
	for i := range serializedEmail.Parts {
		part := &serializedEmail.Parts[i]
		if contentTypes, ok := part.Headers["content-type"]; ok {
			for _, ct := range contentTypes {
				if strings.Contains(ct, "message/rfc822") {
					return part
				}
			}
		}
		// Also check the ContentType field
		if strings.Contains(part.ContentType, "message/rfc822") {
			return part
		}
	}
	return nil
}

// parseAmasha parses the amasha email format
func parseAmasha(body, subject, dateFallback string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	var relevantHeaders []string

	if strings.Contains(strings.ToLower(body), "attached email as spam") {
		part := getPartWithAttachment(serializedEmail)
		if part != nil && part.Body != nil {
			// Convert Body interface{} to string
			if bodyStr, ok := part.Body.(string); ok && bodyStr != "" {
				relevantHeaders = getRelevantHeaders(bodyStr)
			}
		}
	} else {
		relevantHeaders = getRelevantHeaders(body)
	}

	if len(relevantHeaders) == 0 {
		return nil, common.NewParserError("no relevant headers found")
	}

	authRes := relevantHeaders[0]

	event := events.NewEvent("amasha")

	// Determine event type based on subject
	subjectLower := strings.ToLower(subject)
	if strings.Contains(subjectLower, "phishing") {
		event.EventTypes = []events.EventType{events.NewPhishing()}
	} else if strings.Contains(subjectLower, "spam") || strings.Contains(subjectLower, "blackmail") {
		event.EventTypes = []events.EventType{events.NewSpam()}
	}

	// Try to extract IP from Authentication-Results
	ip := common.ExtractOneIP(authRes)
	if ip != "" {
		event.IP = ip
		event.EventDate = email.ParseDate(dateFallback)
		return []*events.Event{event}, nil
	}

	return nil, common.NewParserError("no ip found")
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, true)
	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	// Get date from headers
	var dateFallback string
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		dateFallback = dateHeader[0]
	}

	// Check if this is a spam, abuse, or phishing report
	if strings.Contains(subjectLower, "spam") ||
		strings.Contains(subjectLower, "abuse") ||
		strings.Contains(subjectLower, "phishing") {
		return parseAmasha(body, subject, dateFallback, serializedEmail)
	}

	return nil, common.NewParserError("unknown email type: " + subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
