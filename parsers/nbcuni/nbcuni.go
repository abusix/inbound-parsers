package nbcuni

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the nbcuni parser
type Parser struct{}

// NewParser creates a new nbcuni parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from NBC Universal's Anti-Piracy Technical Operations
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get subject
	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, &common.ParserError{Message: "subject header not found"}
	}

	// Verify this is a copyright infringement notice
	if !strings.Contains(subject, "Notice of Copyright Infringement") {
		return nil, &common.ParserError{Message: "not a copyright infringement notice"}
	}

	// Parse copyright reports
	return parseCopyright(serializedEmail)
}

// parseCopyright extracts copyright infringement data from the email body
func parseCopyright(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, &common.ParserError{Message: "email body is empty"}
	}

	marker := "Anti-Piracy Technical Operations"
	index := strings.LastIndex(body, marker)
	if index == -1 {
		return nil, &common.ParserError{Message: "marker not found in body"}
	}

	// Extract the relevant section and skip first 6 lines after marker
	bodySection := body[index:]
	bodyLines := strings.Split(bodySection, "\n")
	if len(bodyLines) <= 6 {
		return nil, &common.ParserError{Message: "not enough lines after marker"}
	}
	bodyLineList := bodyLines[6:]

	// Parse film names and associated URLs
	films := make(map[string]bool)
	filmListURL := make(map[string]map[string]bool)
	filmListDomain := make(map[string]map[string]bool)

	var filmName string

	for _, line := range bodyLineList {
		// Stop at separator
		if strings.Contains(line, "--") {
			break
		}

		line = strings.TrimSpace(line)

		// Empty line resets current film name
		if line == "" {
			filmName = ""
			continue
		}

		// Check if line is a URL
		if strings.HasPrefix(line, "http") || strings.HasPrefix(line, "hxxp") {
			if filmName != "" {
				filmListURL[filmName][line] = true
				domain := extractDomain(line)
				if domain != "" {
					filmListDomain[filmName][domain] = true
				}
			}
		} else {
			// This is a film name
			filmName = line
			films[line] = true
			filmListURL[line] = make(map[string]bool)
			filmListDomain[line] = make(map[string]bool)
		}
	}

	// Create events
	var result []*events.Event

	for film := range films {
		for url := range filmListURL[film] {
			event := events.NewEvent("nbcuni")
			event.URL = url

			// Set event date
			if serializedEmail.Headers != nil {
				if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
					event.EventDate = email.ParseDate(dates[0])
				}
			}

			// Create copyright event type
			copyrightType := events.NewCopyright(film, "", "")
			event.EventTypes = []events.EventType{copyrightType}

			result = append(result, event)
		}
	}

	if len(result) == 0 {
		return nil, &common.ParserError{Message: "no events created"}
	}

	return result, nil
}

// extractDomain extracts the domain from a URL
func extractDomain(url string) string {
	// Clean up obfuscated URLs
	url = strings.ReplaceAll(url, "hxxp", "http")

	// Remove protocol prefix
	parts := strings.SplitN(url, "://", 2)
	domainPart := url
	if len(parts) == 2 {
		domainPart = parts[1]
	}

	// Extract domain (everything before first /)
	if idx := strings.Index(domainPart, "/"); idx != -1 {
		domainPart = domainPart[:idx]
	}

	return domainPart
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
