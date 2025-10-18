package mcgill

import (
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// getForwardedMessage extracts the forwarded message from the body starting at "received:"
func getForwardedMessage(body string) map[string][]string {
	idx := strings.Index(body, "received:")
	if idx == -1 {
		return nil
	}

	forwardedText := body[idx:]
	headers := make(map[string][]string)

	// Parse headers from the forwarded message
	lines := strings.Split(forwardedText, "\n")
	var currentHeader string
	var currentValue strings.Builder

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")

		// Check if line starts with whitespace (continuation of previous header)
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if currentHeader != "" {
				currentValue.WriteString(" ")
				currentValue.WriteString(strings.TrimSpace(line))
			}
			continue
		}

		// Save previous header if any
		if currentHeader != "" {
			headers[currentHeader] = append(headers[currentHeader], currentValue.String())
			currentValue.Reset()
		}

		// Parse new header
		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			currentHeader = ""
			continue
		}

		currentHeader = strings.ToLower(strings.TrimSpace(line[:colonIdx]))
		currentValue.WriteString(strings.TrimSpace(line[colonIdx+1:]))
	}

	// Save last header
	if currentHeader != "" {
		headers[currentHeader] = append(headers[currentHeader], currentValue.String())
	}

	return headers
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Convert to lowercase for parsing
	bodyLower := strings.ToLower(body)

	// Get first non-empty line
	var firstLine string
	for _, line := range strings.Split(bodyLower, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			firstLine = trimmed
			break
		}
	}

	if firstLine == "" {
		return nil, common.NewParserError("Empty body")
	}

	// Check if 'spam' is in the first line
	if !strings.Contains(firstLine, "spam") {
		return nil, common.NewParserError("'spam' not found in first line of body")
	}

	// Try to extract IP from first line
	ip := common.ExtractOneIP(firstLine)

	// Get forwarded message headers
	forwardedHeaders := getForwardedMessage(bodyLower)
	if forwardedHeaders == nil {
		return nil, common.NewParserError("No forwarded message found")
	}

	// If no IP in first line, try Authentication-Results header
	if ip == "" {
		if authResults, ok := forwardedHeaders["authentication-results"]; ok && len(authResults) > 0 {
			ip = common.ExtractOneIP(authResults[0])
		}

		if ip == "" {
			return nil, common.NewParserError("No IP found")
		}
	}

	// Get Received headers from forwarded message
	var eventDate *time.Time
	if receivedHeaders, ok := forwardedHeaders["received"]; ok && len(receivedHeaders) > 0 {
		// Find the first received header containing the IP
		significantReceived := ""
		for _, received := range receivedHeaders {
			if strings.Contains(received, ip) {
				significantReceived = received
				break
			}
		}

		// If no match found, use first Received header
		if significantReceived == "" {
			significantReceived = receivedHeaders[0]
		}

		// Extract date from Received header (after semicolon)
		if idx := strings.LastIndex(significantReceived, ";"); idx != -1 {
			dateStr := strings.TrimSpace(significantReceived[idx+1:])
			eventDate = email.ParseDate(dateStr)
		}
	}

	// Create event
	event := events.NewEvent("mcgill")
	event.EventDate = eventDate
	event.IP = ip
	event.EventTypes = []events.EventType{events.NewSpam()}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
