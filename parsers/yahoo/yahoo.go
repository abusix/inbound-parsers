package yahoo

import (
	"fmt"
	"net/mail"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// Match determines how to handle emails from Yahoo senders
// Returns: "reject", "rewrite", "parse", or "ignore"
func Match(serializedEmail *email.SerializedEmail, fromAddr string) string {
	if fromAddr == "" {
		return "ignore"
	}

	// Check for audriusvaitiekunas@yahoo.com
	if fromAddr == "audriusvaitiekunas@yahoo.com" {
		subject, _ := common.GetSubject(serializedEmail, false)
		if strings.Contains(strings.ToLower(subject), "re:") {
			return "reject"
		}
		return "rewrite"
	}

	// Check for aroc725@yahoo.com
	if fromAddr == "aroc725@yahoo.com" {
		return "parse"
	}

	return "ignore"
}

// Rewrite rewrites emails from audriusvaitiekunas@yahoo.com
// Extracts the forwarded message and returns the actual sender
func Rewrite(serializedEmail *email.SerializedEmail, fromAddr string) (*email.SerializedEmail, string, string, error) {
	if fromAddr == "audriusvaitiekunas@yahoo.com" {
		return rewriteAudriusvaitiekunas(serializedEmail)
	}

	return serializedEmail, fromAddr, "", nil
}

// rewriteAudriusvaitiekunas handles forwarded messages from audriusvaitiekunas@yahoo.com
func rewriteAudriusvaitiekunas(serializedEmail *email.SerializedEmail) (*email.SerializedEmail, string, string, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, "", "", err
	}

	// Split on "Begin forwarded message:"
	parts := strings.SplitN(body, "Begin forwarded message:", 2)
	if len(parts) < 2 {
		return nil, "", "", fmt.Errorf("no forwarded message found")
	}

	forwardedPart := parts[1]

	// Extract the forwarded body (after "wrote:")
	wroteParts := strings.SplitN(forwardedPart, "wrote:", 2)
	if len(wroteParts) < 2 {
		return nil, "", "", fmt.Errorf("no 'wrote:' marker found in forwarded message")
	}

	forwardedBody := strings.TrimSpace(wroteParts[1])

	// Extract actual sender from before "wrote:"
	// Format: "On Thursday, October 14, 2021, 7:32 PM, BitNinja <incident@bitninja.info> wrote:"
	beforeWrote := wroteParts[0]
	commaParts := strings.Split(beforeWrote, ",")
	if len(commaParts) == 0 {
		return nil, "", "", fmt.Errorf("could not parse sender from forwarded message")
	}

	// Parse the email address from the last comma-separated part
	lastPart := commaParts[len(commaParts)-1]
	addr, err := mail.ParseAddress(strings.TrimSpace(lastPart))

	var actualFromAddr, actualFromName string
	if err != nil {
		// If parsing fails, try to extract manually
		actualFromAddr = extractEmailAddress(lastPart)
		actualFromName = ""
	} else {
		actualFromAddr = strings.ToLower(addr.Address)
		actualFromName = addr.Name
	}

	// Update the email body
	serializedEmail.Body = forwardedBody

	// Update subject if it starts with "Fw:"
	subject, _ := common.GetSubject(serializedEmail, false)
	if strings.HasPrefix(subject, "Fw:") {
		newSubject := strings.TrimSpace(subject[3:])
		if serializedEmail.Headers != nil {
			serializedEmail.Headers["subject"] = []string{newSubject}
		}
	}

	return serializedEmail, actualFromAddr, actualFromName, nil
}

// Parse parses emails from aroc725@yahoo.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	fromAddr, err := common.GetFrom(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	if fromAddr == "aroc725@yahoo.com" {
		return parseAroc725(serializedEmail)
	}

	return nil, fmt.Errorf("yahoo parser called with unsupported sender: %s", fromAddr)
}

// parseAroc725 handles spam/phishing reports from aroc725@yahoo.com
func parseAroc725(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, _ := common.GetSubject(serializedEmail, false)

	// Handle phishing reports
	if strings.Contains(subject, "PHISHING ATTEMPT") {
		event := events.NewEvent("yahoo")

		// Get event date from email header
		if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
			event.EventDate = email.ParseDate(dateHeader[0])
		}

		event.EventTypes = []events.EventType{events.NewPhishing()}

		// Extract URL
		url := common.GetLineAfter(body, "The following URL", 1)
		event.URL = strings.TrimSpace(url)

		return []*events.Event{event}, nil
	}

	// Handle spam reports
	if !strings.Contains(strings.ToLower(body), "spam") {
		return nil, fmt.Errorf("aroc725@yahoo.com is sending new types (not spam or phishing)")
	}

	// Extract the forwarded message
	parts := strings.SplitN(body, "----- Forwarded Message -----", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("no forwarded message found")
	}

	original := strings.TrimSpace(parts[1])

	event := events.NewEvent("yahoo")
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Extract IP from X-Originating-Ip header
	ip := common.FindStringWithoutMarkers(original, "X-Originating-Ip:", "")
	event.IP = strings.TrimSpace(ip)

	// Extract event date from X-Apparently-To header
	xApparentlyTo := common.FindStringWithoutMarkers(original, "X-Apparently-To:", "")
	dateParts := strings.Split(xApparentlyTo, ";")
	if len(dateParts) > 1 {
		dateStr := strings.TrimSpace(dateParts[len(dateParts)-1])
		event.EventDate = email.ParseDate(dateStr)
	}

	// Parse the original email headers
	originalHeaders := parseEmailHeaders(original)

	// Add email event detail
	fromAddr := ""
	if from, ok := originalHeaders["from"]; ok && len(from) > 0 {
		fromAddr = from[0]
	}

	toAddr := ""
	if to, ok := originalHeaders["to"]; ok && len(to) > 0 {
		toAddr = to[0]
	}

	event.AddEventDetail(&events.Email{
		FromAddress: fromAddr,
		ToAddress:   toAddr,
	})

	return []*events.Event{event}, nil
}

// parseEmailHeaders parses email headers from a raw email string
// This mimics Python's email.message_from_string
func parseEmailHeaders(rawEmail string) map[string][]string {
	headers := make(map[string][]string)

	// Parse using Go's mail package
	msg, err := mail.ReadMessage(strings.NewReader(rawEmail))
	if err != nil {
		// If parsing fails, try to extract headers manually
		return extractHeadersManually(rawEmail)
	}

	// Convert mail.Header to map[string][]string
	for key := range msg.Header {
		values := msg.Header[key]
		headers[strings.ToLower(key)] = values
	}

	return headers
}

// extractHeadersManually manually extracts headers from raw email
func extractHeadersManually(rawEmail string) map[string][]string {
	headers := make(map[string][]string)

	lines := strings.Split(rawEmail, "\n")
	for _, line := range lines {
		// Stop at first empty line (end of headers)
		if strings.TrimSpace(line) == "" {
			break
		}

		// Parse header line
		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(line[:colonIdx]))
		value := strings.TrimSpace(line[colonIdx+1:])

		headers[key] = append(headers[key], value)
	}

	return headers
}

// extractEmailAddress extracts email address from a string
func extractEmailAddress(s string) string {
	s = strings.TrimSpace(s)

	// Check for <email@example.com> format
	if startIdx := strings.Index(s, "<"); startIdx != -1 {
		if endIdx := strings.Index(s[startIdx:], ">"); endIdx != -1 {
			return strings.ToLower(strings.TrimSpace(s[startIdx+1 : startIdx+endIdx]))
		}
	}

	// Return as-is if no brackets found
	return strings.ToLower(strings.TrimSpace(s))
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
