package wisc

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/parsers/common"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// Match determines if this parser should process the email
// Returns true if from address is postmaster@wisc.edu
// Note: Python version rejects newmails@wisc.edu and newms@wisc.edu
func Match(fromAddr string) bool {
	fromAddr = strings.ToLower(strings.TrimSpace(fromAddr))

	// REJECT these addresses (return false)
	if fromAddr == "newmails@wisc.edu" || fromAddr == "newms@wisc.edu" {
		return false
	}

	// PARSE this address (return true)
	if fromAddr == "postmaster@wisc.edu" {
		return true
	}

	// IGNORE all others (return false)
	return false
}

// Parse parses WISC phishing reports
// Python reference: abusix_parsers/parsers/parser/wisc.py
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get subject and verify it's "phish report"
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get subject: %w", err)
	}

	subjectLower := strings.ToLower(strings.TrimSpace(subject))
	if subjectLower != "phish report" {
		return nil, fmt.Errorf("unexpected subject: %s", subject)
	}

	// Find .eml attachment
	emlContent, err := common.FindFirstAttachmentWithMimeType(serializedEmail, ".eml")
	if err != nil {
		return nil, fmt.Errorf("failed to find .eml attachment: %w", err)
	}

	// Parse the .eml attachment
	parsedMsg, err := mail.ReadMessage(strings.NewReader(emlContent))
	if err != nil {
		return nil, fmt.Errorf("failed to parse .eml attachment: %w", err)
	}

	// Extract IP from X-Spam-PmxInfo header
	ipAddress := ""
	if pmxInfo := parsedMsg.Header.Get("X-Spam-PmxInfo"); pmxInfo != "" {
		ipPattern := regexp.MustCompile(`SenderIP=\[(?P<ip>\S+)\]`)
		if match := ipPattern.FindStringSubmatch(pmxInfo); match != nil {
			for i, name := range ipPattern.SubexpNames() {
				if name == "ip" && i < len(match) {
					ipAddress = match[i]
					break
				}
			}
		}
	}

	// Read the attachment body
	bodyBytes := make([]byte, 10*1024*1024) // 10MB limit for safety
	n, _ := parsedMsg.Body.Read(bodyBytes)
	attachmentBody := string(bodyBytes[:n])

	// Extract URL from attachment body
	urlStr := ""
	urlPattern := regexp.MustCompile(`(?P<url>https?://\S+)`)
	if match := urlPattern.FindStringSubmatch(attachmentBody); match != nil {
		for i, name := range urlPattern.SubexpNames() {
			if name == "url" && i < len(match) {
				urlStr = match[i]
				break
			}
		}
	}

	// Clean up URL trailing characters
	if urlStr != "" {
		urlStr = strings.TrimSuffix(urlStr, ",")
		urlStr = strings.TrimSuffix(urlStr, ")")
		urlStr = strings.TrimSuffix(urlStr, ">")
	}

	// Only create event if we have IP or URL
	if ipAddress == "" && urlStr == "" {
		return nil, fmt.Errorf("no IP or URL found in attachment")
	}

	// Create event
	event := events.NewEvent("wisc")
	event.EventTypes = []events.EventType{events.NewPhishing()}
	event.IP = ipAddress
	event.URL = urlStr

	// Get event date from original email
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
