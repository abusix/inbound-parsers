package gold_parser

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// IP_PATTERN matches IP addresses with possible obfuscation (brackets around dots)
var ipPattern = regexp.MustCompile(`(\[?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\]?)`)

// URL_PATTERN matches "URL's:" followed by a URL
var urlPattern = regexp.MustCompile(`(?i)(URL\'s:)[^h.]*(\S+)`)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// parseBot handles emails with "botnet" in subject
func parseBot(body string, event *events.Event, dateFallback string) ([]*events.Event, error) {
	// Try to parse date from body
	dateStr := common.FindStringWithoutMarkers(body, "date ", "")
	if dateStr != "" {
		event.EventDate = email.ParseDate(dateStr)
	}

	// If date parsing failed, use fallback from email header
	if event.EventDate == nil && dateFallback != "" {
		event.EventDate = email.ParseDate(dateFallback)
	}

	// Set event type to Bot
	event.EventTypes = []events.EventType{events.NewBot("")}

	// Extract IP address
	if ipMatch := ipPattern.FindStringSubmatch(body); len(ipMatch) > 1 {
		ip := ipMatch[1]
		// Clean up obfuscation: replace [.] with .
		ip = strings.ReplaceAll(ip, "[.]", ".")
		ip = strings.TrimSpace(ip)

		// Validate it's not empty after cleaning
		if ip != "" {
			event.IP = ip
		} else {
			return nil, common.NewParserError("Couldn't find IP")
		}
	}

	// Extract URL
	if urlMatch := urlPattern.FindStringSubmatch(body); len(urlMatch) > 2 {
		event.URL = urlMatch[2]
	}

	// Only return event if we have either IP or URL
	if event.IP != "" || event.URL != "" {
		return []*events.Event{event}, nil
	}

	return nil, common.NewParserError("No IP or URL found")
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get body and subject
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Create event
	event := events.NewEvent("gold_parser")

	// Get date fallback from headers
	var dateFallback string
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		dateFallback = dateHeader[0]
	}

	// Check subject for botnet
	if strings.Contains(strings.ToLower(subject), "botnet") {
		return parseBot(body, event, dateFallback)
	}

	// If subject doesn't contain "botnet", raise NewTypeError equivalent
	return nil, common.NewParserError("unknown subject type: " + subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 16
}
