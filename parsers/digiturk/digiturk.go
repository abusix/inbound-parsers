package digiturk

import (
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
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Replace " :" with ":" as in Python version
	body = strings.ReplaceAll(body, " :", ":")

	// Extract description
	description := common.FindStringWithoutMarkers(body, "Description of The Copyrighted Work:", "")
	description = strings.TrimSpace(description)

	// Extract official URL
	officialURL := common.FindStringWithoutMarkers(body, "Original Location of the Copyrighted Work:", "")
	officialURL = strings.TrimSpace(officialURL)
	// Take only the first word (URL)
	if parts := strings.Fields(officialURL); len(parts) > 0 {
		officialURL = parts[0]
	}

	// Extract IP and URL from the location block
	block := common.GetContinuousLinesUntilEmptyLine(body, "Identification of the Location of The Material")
	ip, url := parseURLAndIP(body, block)

	// Create event
	event := events.NewEvent("digiturk")

	// Create Copyright event type with official URL and copyrighted work type (description)
	copyright := events.NewCopyright("", "", "")
	copyright.OfficialURL = officialURL
	copyright.CopyrightedWork = description
	event.EventTypes = []events.EventType{copyright}

	event.IP = ip
	event.URL = url

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	return []*events.Event{event}, nil
}

// parseURLAndIP extracts IP and URL from a block of lines
func parseURLAndIP(body string, block []string) (string, string) {
	var ip, url string

	for _, line := range block {
		if common.ExtractOneIP(line) != "" {
			ip = line
		} else {
			trimmed := strings.TrimSpace(line)
			if trimmed == "Domain:" {
				// Recursively parse the block after "Domain:"
				newBlock := common.GetBlockAfterWithStop(body, "Domain:", "")
				return parseURLAndIP(body, newBlock)
			} else if strings.Contains(line, "Domain:") {
				// Extract URL after "Domain:"
				parts := strings.SplitN(line, ":", 2)
				if len(parts) > 1 {
					url = parts[1]
				}
			} else {
				url = line
			}
		}
	}

	return ip, url
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
