// Package ricomanagement implements the ricomanagement parser
package ricomanagement

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the ricomanagement parser
type Parser struct{}

// Parse parses emails from @ricomanagement
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Check for expected subject format
	if !strings.Contains(subject, "Infringement") {
		return nil, common.NewNewTypeError("Adapt the parser")
	}

	// Get date fallback from headers
	dateFallback := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateFallback = dateHeaders[0]
	}

	// Extract details from "infringed:" section
	details := common.GetBlockAfterWithStop(body, "infringed:", "")
	if len(details) == 0 {
		return nil, common.NewParserError("Format changed adapt the parser")
	}

	var title, owner, officialURL string

	// Parse the details - can be 3 or 4 lines
	if len(details) == 3 {
		// No title, just owner and official_url
		owner = details[0]
		officialURL = details[1]
		title = ""
	} else if len(details) >= 4 {
		// Has title
		title = details[0]
		owner = details[1]
		officialURL = details[2]
	} else {
		return nil, common.NewParserError("Format changed adapt the parser")
	}

	// Process official URL
	if strings.Contains(officialURL, "example of work:") {
		parts := strings.SplitN(officialURL, ":", 2)
		if len(parts) > 1 {
			officialURL = strings.TrimSpace(parts[1])
		}
	} else {
		officialURL = ""
	}

	// Extract URLs and IP from "infringing:" section
	infringingLines := common.GetBlockAfterWithStop(body, "infringing:", "")

	urlSet := make(map[string]bool)
	ip := ""

	for _, line := range infringingLines {
		lineLower := strings.ToLower(line)
		if strings.Contains(line, "http") {
			urlSet[line] = true
		} else if strings.Contains(lineLower, "ip address:") {
			ip = line
		}
	}

	// Create events for each URL
	var result []*events.Event
	for url := range urlSet {
		event := events.NewEvent("ricomanagement")

		// Set event date
		eventDate := email.ParseDate(dateFallback)
		event.EventDate = eventDate

		// Set IP and URL
		event.IP = ip
		event.URL = url

		// Create copyright event type
		copyright := events.NewCopyright(title, owner, "")
		if officialURL != "" {
			copyright.OfficialURL = strings.TrimSpace(officialURL)
		}
		event.EventTypes = []events.EventType{copyright}

		result = append(result, event)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
