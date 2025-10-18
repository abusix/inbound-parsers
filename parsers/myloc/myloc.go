// Package myloc implements the myloc.de parser
package myloc

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the myloc parser
type Parser struct{}

var (
	ipPattern = regexp.MustCompile(`(?i)(IP:\s*)(?P<ip>\[?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\]?)`)
)

// Parse parses emails from @myloc.de
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Get date fallback
	dateFallback := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateFallback = dateHeaders[0]
	}

	subjectLower := strings.ToLower(subject)

	// Check for DMCA/Copyright reports
	if strings.Contains(subjectLower, "dmca") ||
		strings.Contains(subjectLower, "copyright") ||
		strings.Contains(subjectLower, "infringement") {
		return parseDMCA(body, dateFallback)
	}

	// Check for phishing reports
	if strings.Contains(subjectLower, "phishing") {
		return parsePhishing(body, subject, dateFallback)
	}

	return nil, common.NewNewTypeError(subject)
}

func parseDMCA(body, dateFallback string) ([]*events.Event, error) {
	var result []*events.Event

	eventDate := email.ParseDate(dateFallback)

	// Try multiple URL section markers
	tags := []string{"Reported URLs:", "> URLs:", "URLs:", "URL:", "imdb link"}
	var urlBlock []string

	for _, tag := range tags {
		if strings.Contains(body, tag) {
			// Ensure tag is on its own line for GetBlockAfter
			bodyWithNewline := strings.ReplaceAll(body, tag, tag+"\n")
			urlBlock = common.GetBlockAfterWithStop(bodyWithNewline, tag, "")
			break
		}
	}

	if len(urlBlock) == 0 {
		return nil, common.NewParserError("No URLs found in DMCA report")
	}

	// Extract copyright owner and original work once
	copyrightOwner := common.FindStringWithoutMarkers(body, "Company Name:", "")
	originalWork := common.FindStringWithoutMarkers(body, "Original Work:", "")
	if !strings.Contains(originalWork, "http") {
		originalWork = ""
	}

	// Parse each URL line
	for _, line := range urlBlock {
		// Remove '>' prefix if present
		if strings.HasPrefix(line, ">") {
			parts := strings.Split(line, ">")
			var cleaned []string
			for _, part := range parts {
				if trimmed := strings.TrimSpace(part); trimmed != "" {
					cleaned = append(cleaned, trimmed)
				}
			}
			if len(cleaned) == 0 {
				break
			}
			line = strings.Join(cleaned, "")
		}

		line = strings.TrimSpace(line)
		if line == "" {
			break
		}

		event := events.NewEvent("myloc")
		event.EventDate = eventDate
		event.EventTypes = []events.EventType{
			events.NewCopyright(originalWork, copyrightOwner, ""),
		}
		event.URL = line

		// Try to extract IP
		if match := ipPattern.FindStringSubmatch(body); len(match) > 2 {
			ipStr := match[2]
			ipStr = strings.ReplaceAll(ipStr, "[.]", ".")
			ipStr = strings.ReplaceAll(ipStr, "[", "")
			ipStr = strings.ReplaceAll(ipStr, "]", "")
			ipStr = strings.TrimSpace(ipStr)

			// Validate it's a proper IP
			if validIP := common.IsIP(ipStr); validIP != "" {
				event.IP = validIP
			}
		}

		result = append(result, event)
	}

	if len(result) == 0 {
		return nil, common.NewParserError("No valid events extracted from DMCA report")
	}

	return result, nil
}

func parsePhishing(body, subject, dateFallback string) ([]*events.Event, error) {
	event := events.NewEvent("myloc")

	eventDate := email.ParseDate(dateFallback)
	event.EventDate = eventDate

	// Extract URL from subject
	url := common.FindStringWithoutMarkers(subject, "attack at", "")
	url = strings.TrimSpace(url)
	event.URL = url

	event.EventTypes = []events.EventType{events.NewPhishing()}

	// Try to extract IP from body
	ipBlock := common.GetNonEmptyLineAfter(body, "on your network:")
	ipBlock = strings.TrimSpace(ipBlock)

	if ipBlock != "" {
		// Validate IP
		if validIP := common.IsIP(ipBlock); validIP != "" {
			event.IP = validIP
		}
	}

	// Must have either IP or URL
	if event.IP == "" && event.URL == "" {
		return nil, common.NewParserError("Unable to find any IP or URL for phishing report")
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
