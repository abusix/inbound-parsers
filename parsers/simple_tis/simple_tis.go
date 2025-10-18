package simple_tis

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the simple_tis abuse report parser
type Parser struct{}

// FROM_TO_SIGNIFICANT_RECEIVED_HINT maps sender addresses to hints in Received headers
var fromToSignificantReceivedHint = map[string]string{
	"@beautypalace.com.mx": "by sv.chchosting.com",
	"@meergus.com":         "by mail.gennadymeergus.com",
	"daniel@mail24.vip":    "by server.ist-immer-online.de",
	"riverara@usa.net":     "usa.net via",
	"admin@attbbi.com":     "your-server.de with",
	"jorge_ferdada@hotmail.com": "protection.outlook.com",
}

// NewParser creates a new Parser instance
func NewParser() *Parser {
	return &Parser{}
}

// getEvidence finds the email part containing received headers
func getEvidence(serializedEmail *email.SerializedEmail) *email.EmailPart {
	for i := range serializedEmail.Parts {
		part := &serializedEmail.Parts[i]
		if part.Headers != nil {
			if _, hasReceived := part.Headers["received"]; hasReceived {
				return part
			}
		}
	}
	return nil
}

// Parse implements the Parser interface
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get from address
	fromAddr, err := common.GetFrom(serializedEmail, false)
	if err != nil || fromAddr == "" {
		return nil, common.NewParserError("no from address found")
	}

	// Check if this parser should handle this email
	var hint string
	matched := false
	for key, value := range fromToSignificantReceivedHint {
		if strings.HasSuffix(fromAddr, key) {
			hint = value
			matched = true
			break
		}
	}

	if !matched {
		return nil, common.NewParserError("from address does not match known senders")
	}

	// Check subject doesn't start with "re:"
	subject, _ := common.GetSubject(serializedEmail, false)
	if strings.HasPrefix(strings.ToLower(subject), "re:") {
		return nil, common.NewParserError("subject starts with re:")
	}

	// Get evidence part
	evidence := getEvidence(serializedEmail)
	if evidence == nil {
		return nil, common.NewParserError("no evidence part with received headers found")
	}

	// Get received headers
	received, ok := evidence.Headers["received"]
	if !ok || len(received) == 0 {
		return nil, common.NewParserError("no received headers found")
	}

	// Find significant received headers containing the hint
	var significantReceived []string
	for _, r := range received {
		if strings.Contains(r, hint) {
			significantReceived = append(significantReceived, r)
		}
	}

	if len(significantReceived) == 0 {
		return nil, common.NewParserError("could not find significant received header")
	}

	// Create event
	event := events.NewEvent("simple_tis")
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Extract IP from significant received headers (iterate in reverse)
	receivedIndex := -1
	for i := len(significantReceived) - 1; i >= 0; i-- {
		header := significantReceived[i]

		// Split by "by" and get the part before it
		parts := strings.Split(header, "by")
		if len(parts) > 0 {
			beforeBy := parts[0]

			// Try to extract IPv4 first
			allIPv4s := common.ExtractAllIPv4(beforeBy)
			if len(allIPv4s) > 0 {
				event.IP = allIPv4s[len(allIPv4s)-1] // Take the last IPv4
				receivedIndex = i
				break
			}

			// Try IPv6 if no IPv4 found
			ipv6 := extractOneIPv6(beforeBy)
			if ipv6 != "" {
				event.IP = ipv6
				receivedIndex = i
				break
			}
		}
	}

	// Extract event date from the received header
	if receivedIndex >= 0 {
		receivedHeader := email.NewReceivedHeader(significantReceived)
		event.EventDate = receivedHeader.ReceivedDate(receivedIndex)
	}

	return []*events.Event{event}, nil
}

// extractOneIPv6 attempts to extract an IPv6 address from text
// This is a simple implementation matching Python's extract_one_ipv6
func extractOneIPv6(text string) string {
	// Clean up common obfuscations
	text = strings.ReplaceAll(text, "[", "")
	text = strings.ReplaceAll(text, "]", "")

	// Look for IPv6 patterns - simplified version
	// A full implementation would use a proper IPv6 regex
	parts := strings.Fields(text)
	for _, part := range parts {
		if strings.Count(part, ":") >= 2 {
			// Likely an IPv6 address
			// Clean it up
			part = strings.Trim(part, "(),;")
			if isValidIPv6Format(part) {
				return part
			}
		}
	}
	return ""
}

// isValidIPv6Format checks if a string looks like an IPv6 address
func isValidIPv6Format(s string) bool {
	// Basic check - should have multiple colons
	colonCount := strings.Count(s, ":")
	if colonCount < 2 || colonCount > 7 {
		return false
	}

	// Check for valid hex characters and structure
	parts := strings.Split(s, ":")
	for _, part := range parts {
		if part == "" {
			continue // Allow :: compression
		}
		if len(part) > 4 {
			return false
		}
		for _, c := range part {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
