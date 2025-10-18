package studiobarbero

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get body and subject (both required)
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	bodyLower := strings.ToLower(body)

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	// Create event
	event := events.NewEvent("studiobarbero")

	// Get event date from headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		event.EventDate = email.ParseDate(dateHeader[0])
	}

	// Extract copyright owner from subject
	// Replace "through" with "(" and extract text between "intellectual property rights of" and "("
	subjectProcessed := strings.ReplaceAll(subjectLower, "through", "(")
	copyrightOwner := common.FindStringWithoutMarkers(
		subjectProcessed,
		"intellectual property rights of",
		"(",
	)
	copyrightOwner = strings.TrimSpace(copyrightOwner)
	// Join whitespace-separated words (normalize spaces)
	copyrightOwner = strings.Join(strings.Fields(copyrightOwner), " ")

	// Set event type with copyright owner
	event.EventTypes = []events.EventType{
		events.NewCopyright("", copyrightOwner, ""),
	}

	// Extract IP address
	// Replace "indirizzo ip" with "ip address" and extract from "(ip address" to ")"
	bodyProcessed := strings.ReplaceAll(bodyLower, "indirizzo ip", "ip address")
	ip := common.FindStringWithoutMarkers(bodyProcessed, "(ip address", ")")
	ip = strings.TrimSpace(ip)
	if ip != "" {
		event.IP = ip
	}

	// Extract URL
	// Replace "website" with "web site", "sito web" with "web site"
	// Extract from "web site " to " "
	bodyProcessed = strings.ReplaceAll(bodyLower, "website", "web site")
	bodyProcessed = strings.ReplaceAll(bodyProcessed, "sito web", "web site")
	urlStr := common.FindStringWithoutMarkers(bodyProcessed, "web site ", " ")
	urlStr = strings.TrimSpace(urlStr)

	// Check if URL is wrapped in angle brackets and extract it
	urlPattern := regexp.MustCompile(`<(?P<url>.*)>,?$`)
	if match := urlPattern.FindStringSubmatch(urlStr); match != nil {
		// Extract the named group
		for i, name := range urlPattern.SubexpNames() {
			if name == "url" && i < len(match) {
				urlStr = match[i]
				break
			}
		}
	}

	// Validate and set URL if valid
	if common.IsURL(urlStr) {
		event.URL = urlStr
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
