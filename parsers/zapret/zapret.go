// Package zapret implements the zapret-info (Russian censorship) parser
package zapret

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the zapret parser
type Parser struct{}

var (
	urlRegex = regexp.MustCompile(`ресурсу (http\S*)`)
)

// Parse parses emails from zapret-info-out@rkn.gov.ru and related addresses
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get reply-to header
	replyTo := ""
	if replyToHeaders, ok := serializedEmail.Headers["reply-to"]; ok && len(replyToHeaders) > 0 {
		replyTo = replyToHeaders[0]
	}

	// Get from address
	fromAddr, _ := common.GetFrom(serializedEmail, false)

	// Get body
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Get date
	eventDate := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = dateHeaders[0]
	}

	// Determine if this is a copyright or censorship event
	if (strings.Contains(replyTo, "nap@rkn.gov.ru") || fromAddr == "nap@rkn.gov.ru") && strings.Contains(body, "copyright") {
		return parseCopyright(serializedEmail, body, eventDate)
	}

	return parseCensorship(serializedEmail, body, eventDate)
}

// parseCopyright parses copyright-related zapret emails
func parseCopyright(serializedEmail *email.SerializedEmail, body, eventDate string) ([]*events.Event, error) {
	event := events.NewEvent("zapret")
	event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}

	// Parse event date
	if eventDate != "" {
		date := email.ParseDate(eventDate)
		event.EventDate = date
	}

	// Extract URL from body - look for "following urls:" marker
	url := common.GetNonEmptyLineAfter(strings.ToLower(body), "following urls:")
	event.URL = url

	if event.URL == "" {
		return nil, common.NewParserError("no URL found in copyright email")
	}

	return []*events.Event{event}, nil
}

// parseCensorship parses censorship-related zapret emails
func parseCensorship(serializedEmail *email.SerializedEmail, body, eventDate string) ([]*events.Event, error) {
	event := events.NewEvent("zapret")
	event.EventTypes = []events.EventType{events.NewCensorship()}

	// Parse event date
	if eventDate != "" {
		date := email.ParseDate(eventDate)
		event.EventDate = date
	}

	// Extract censored URL or IP
	if err := extractCensoredURLIfExists(body, event); err != nil {
		return nil, err
	}

	if event.URL == "" && event.IP == "" {
		return nil, common.NewParserError("no URL or IP found in censorship email")
	}

	return []*events.Event{event}, nil
}

// extractCensoredURLIfExists extracts the censored URL or IP from the email body
func extractCensoredURLIfExists(bodyDecoded string, event *events.Event) error {
	// Check for specific violation text
	if strings.Contains(bodyDecoded, "violation of the distribution of information") {
		url := common.GetNonEmptyLineAfter(bodyDecoded, "URLs:")
		event.URL = url
		return nil
	}

	// Process line by line
	lines := strings.Split(bodyDecoded, "\n")
	for _, line := range lines {
		// Check for "It is notice of" pattern
		if strings.HasPrefix(line, "It is notice of") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) < 2 {
				return common.NewParserError("no url found")
			}
			url := strings.Trim(parts[1], ". ")
			event.URL = url
			return nil
		}

		// Check for "notice on restricting access" pattern
		if strings.Contains(line, "notice on restricting access") {
			ipOrURL := common.FindStringWithoutMarkers(line, "information resource", "in information")
			if ipOrURL == "" {
				return common.NewParserError("no url or ip found")
			}

			// Split and get the second part
			parts := strings.Fields(ipOrURL)
			if len(parts) < 2 {
				return common.NewParserError("no url or ip found")
			}
			ipOrURL = parts[1]

			// Try to extract IP from line
			ip := common.ExtractOneIP(line)

			// Check for Russian URL pattern if no IP found
			if ipOrURL == "" && ip == "" {
				if matches := urlRegex.FindStringSubmatch(bodyDecoded); len(matches) > 1 {
					event.URL = matches[1]
					return nil
				}
			}

			// Set IP if found, otherwise use ipOrURL as URL
			if ip != "" {
				event.IP = ip
			} else {
				event.URL = ipOrURL
			}
			return nil
		}
	}

	return common.NewParserError("no url found")
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
