// Package netresult implements the NetResult parser for copyright and trademark infringement reports
package netresult

import (
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the NetResult parser
type Parser struct{}

// NewParser creates a new NetResult parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from @notices.nr-online.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, _ := common.GetSubject(serializedEmail, false)

	// Get sender email
	fromAddr, _ := common.GetFrom(serializedEmail, false)
	senderEmail := "report@" + extractDomain(fromAddr)

	// Get event date from email headers
	var eventDate *time.Time
	if headers := serializedEmail.Headers; headers != nil {
		if dateHeader, ok := headers["date"]; ok && len(dateHeader) > 0 {
			eventDate = email.ParseDate(dateHeader[0])
		}
	}

	// Create base event
	event := events.NewEvent("netresult")
	event.SenderEmail = senderEmail
	event.EventDate = eventDate

	// Determine if this is a trademark or copyright report
	if strings.Contains(body, "and of such trademarks is an infringement") {
		return p.parseTrademark(body, event)
	}
	return p.parseCopyright(body, event, subject)
}

// parseCopyright handles copyright infringement reports
func (p *Parser) parseCopyright(body string, event *events.Event, subject string) ([]*events.Event, error) {
	// Find reference ID
	referenceID := common.FindStringWithoutMarkers(body, "NetResult Internal Reference:", "")
	if referenceID == "" {
		referenceID = common.FindStringWithoutMarkers(body, "NetResult internal reference:", "")
	}
	if referenceID == "" {
		referenceID = common.FindStringWithoutMarkers(subject+"$", "CaseID-", "$")
	}

	// Find IP address
	ipStr := searchForStringData(body, []searchPair{
		{"From IP:", ""},
		{"IP Address:", ""},
	})

	// Remove carriage returns for easier parsing
	body = strings.ReplaceAll(body, "\r", "")

	// Find URL and date
	url := findString(body, "http", " ")
	var dateStr string

	if url == "" {
		// Alternative format: extract from block after specific marker
		lines := common.GetBlockAfterWithStop(body, "on the web pages listed below", "")
		if len(lines) >= 2 {
			dateLine := lines[0]
			url = lines[1]

			// Extract time from parentheses and replace ET with EST
			timeStr := common.FindStringWithoutMarkers(dateLine, "(", ")")
			timeStr = strings.ReplaceAll(timeStr, "ET", "EST")

			// Parse date parts
			parts := strings.Split(dateLine, "-")
			if len(parts) >= 3 {
				year := strings.TrimSpace(parts[0])
				month := strings.TrimSpace(parts[1])
				day := strings.TrimSpace(parts[2])
				dateStr = day + " " + month + " " + year + " " + timeStr
			}
		}
	} else {
		dateStr = common.FindStringWithoutMarkers(body, "Monitored at:", "")
	}

	// Set IP if valid
	if ipStr != "" {
		if validIP := common.IsIP(ipStr); validIP != "" {
			event.IP = validIP
		} else if url == "" {
			// If no URL and invalid IP, this is an error
			return nil, common.NewParserError("invalid IP address and no URL found")
		}
	}

	// Find copyright owner
	owner := common.FindStringWithoutMarkers(body, "owned by ", "")
	owner = strings.Trim(owner, ". \t\n")
	if strings.HasPrefix(owner, "the") && len(owner) > 4 {
		owner = owner[4:]
	}

	// Add copyright event type
	event.EventTypes = []events.EventType{
		events.NewCopyright("", owner, ""),
	}

	// Set URL
	event.URL = url

	// Add external ID
	if referenceID != "" {
		event.AddEventDetail(&events.ExternalID{
			ID: strings.TrimSpace(referenceID),
		})
	}

	// Set event date if found
	if dateStr != "" {
		parsedDate := email.ParseDate(dateStr)
		if parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	return []*events.Event{event}, nil
}

// parseTrademark handles trademark infringement reports
func (p *Parser) parseTrademark(body string, event *events.Event) ([]*events.Event, error) {
	// Find reference ID
	referenceID := common.FindStringWithoutMarkers(body, "Internal Reference:", "")

	// Find URL
	url := common.FindStringWithoutMarkers(body, "We have noticed that your website, ", " ")
	url = strings.TrimSpace(url)

	if url == "" {
		return nil, common.NewParserError("no url found")
	}

	// Set event properties
	event.URL = url

	// Add external ID
	if referenceID != "" {
		event.AddEventDetail(&events.ExternalID{
			ID: strings.TrimSpace(referenceID),
		})
	}

	// Add trademark event type
	event.EventTypes = []events.EventType{
		events.NewTrademark("", nil, "", ""),
	}

	return []*events.Event{event}, nil
}

// searchPair represents a start/end marker pair for searching
type searchPair struct {
	start string
	end   string
}

// searchForStringData searches for data using multiple marker pairs
func searchForStringData(base string, searchers []searchPair) string {
	for _, pair := range searchers {
		result := common.FindStringWithoutMarkers(base, pair.start, pair.end)
		result = strings.TrimSpace(result)
		if result != "" {
			return result
		}
	}
	return ""
}

// findString finds text between start and end markers
func findString(text, startMarker, endMarker string) string {
	startIdx := strings.Index(text, startMarker)
	if startIdx == -1 {
		return ""
	}

	remaining := text[startIdx:]
	endIdx := strings.Index(remaining, endMarker)
	if endIdx == -1 {
		return ""
	}

	return remaining[:endIdx]
}

// extractDomain extracts domain from email address
func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		return parts[1]
	}
	return email
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
