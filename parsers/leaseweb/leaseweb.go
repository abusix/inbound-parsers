package leaseweb

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/parsers/spamcop"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("email body is empty")
	}

	subject, _ := common.GetSubject(serializedEmail, false)

	// Extract ticket ID from subject [TICKET-ID]
	ticketID := common.FindStringWithoutMarkers(subject, "[", "]")

	// Check for compromised website reports
	if strings.Contains(body, "compromised") {
		return parseNewFormat(serializedEmail, body, events.NewCompromisedWebsite(""), ticketID)
	}

	// Check for scam/fraud reports
	if strings.Contains(body, "scam") {
		return parseNewFormat(serializedEmail, body, events.NewFraud(), ticketID)
	}

	// Check for trademark reports
	if strings.Contains(body, "trademark") {
		return parseTrademark(serializedEmail, body, ticketID)
	}

	// Try spamcop parser on original notification
	marker := "Original notification is placed below"
	originalBody := ""
	if idx := strings.Index(body, marker); idx != -1 {
		originalBody = body[idx+len(marker):]
	}

	if originalBody != "" {
		// Create a modified email with just the original body
		modifiedEmail := *serializedEmail
		modifiedEmail.Body = strings.TrimSpace(originalBody)

		// Try spamcop parser
		spamcopParser := spamcop.NewParser()
		parsedEvents, err := spamcopParser.Parse(&modifiedEmail)
		if err == nil && len(parsedEvents) > 0 {
			// Add ticket ID to events
			for _, event := range parsedEvents {
				event.Parser = "leaseweb"
				event.AddEventDetail(&events.ExternalID{ID: ticketID})
			}
			return parsedEvents, nil
		}
	}

	// Fallback to simple format parsing
	return parseSimpleFormat(body, ticketID)
}

// parseSimpleFormat handles the simple spamvertised format
func parseSimpleFormat(body, ticketID string) ([]*events.Event, error) {
	// Extract block around "Spamvertised web site:"
	block := common.GetBlockAround(body, "Spamvertised web site:")
	if len(block) < 3 {
		return nil, common.NewParserError("insufficient data in simple format")
	}

	event := events.NewEvent("leaseweb")
	event.EventTypes = []events.EventType{events.NewSpamvertised()}

	// First line contains the URL
	url := common.FindStringWithoutMarkers(block[0], "Spamvertised web site:", "")
	event.URL = strings.TrimSpace(url)

	// Third line contains the IP
	if validIP := common.IsIP(block[2]); validIP != "" {
		event.IP = validIP
	}

	// Set event date from header
	event.AddEventDetail(&events.ExternalID{ID: ticketID})

	return []*events.Event{event}, nil
}

// parseNewFormat handles the new format with hxxp[url] [ip] pattern
func parseNewFormat(serializedEmail *email.SerializedEmail, body string, eventType events.EventType, ticketID string) ([]*events.Event, error) {
	// Pattern: hxxp[url] [ip]
	pattern := regexp.MustCompile(`(hxxp[^\s]*) \[(.*?)\]`)
	matches := pattern.FindStringSubmatch(body)

	if len(matches) < 3 {
		return nil, common.NewParserError("url/ip pair not found")
	}

	url := matches[1]
	ip := matches[2]

	event := events.NewEvent("leaseweb")
	event.EventTypes = []events.EventType{eventType}

	// Set event date from headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		event.EventDate = email.ParseDate(dateHeader[0])
	}

	// Set IP
	if validIP := common.IsIP(ip); validIP != "" {
		event.IP = validIP
	}

	// Clean and set URL
	event.URL = common.CleanURL(url)

	// Add external ID
	event.AddEventDetail(&events.ExternalID{ID: ticketID})

	return []*events.Event{event}, nil
}

// parseTrademark handles trademark infringement reports
func parseTrademark(serializedEmail *email.SerializedEmail, body, ticketID string) ([]*events.Event, error) {
	event := events.NewEvent("leaseweb")

	// Set event date from headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		event.EventDate = email.ParseDate(dateHeader[0])
	}

	// Add external ID
	event.AddEventDetail(&events.ExternalID{ID: ticketID})

	// Extract URL
	url := common.GetNonEmptyLineAfter(body, "the below URL")
	event.URL = strings.TrimSpace(url)

	// Extract IP - try two patterns
	ip := common.FindStringWithoutMarkers(body, "hosted on IP ", " ")
	if ip == "" {
		ip = common.FindStringWithoutMarkers(body, "server with IP ", " ")
	}
	if validIP := common.IsIP(ip); validIP != "" {
		event.IP = validIP
	}

	// Extract trademark information
	registryInfo := common.GetBlockAfterWithStop(body, "of the following trademarks", "")

	owner := ""
	number := ""
	if len(registryInfo) >= 2 {
		owner = strings.TrimSpace(registryInfo[0])
		// Extract number after "no."
		if idx := strings.Index(registryInfo[1], "no."); idx != -1 {
			number = strings.TrimSpace(registryInfo[1][idx+3:])
		}
	}

	// Extract country from "place of business at"
	country := ""
	countryText := common.FindStringWithoutMarkers(body, "place of business at", ".")
	if countryText != "" {
		parts := strings.Split(countryText, ",")
		if len(parts) > 0 {
			country = strings.TrimSpace(parts[len(parts)-1])
		}
	}

	// Create trademark event type
	registrationNumbers := []string{}
	if number != "" {
		registrationNumbers = append(registrationNumbers, number)
	}

	event.EventTypes = []events.EventType{
		events.NewTrademark(country, registrationNumbers, owner, ""),
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
