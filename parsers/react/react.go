package react

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	urlPattern = regexp.MustCompile(`URL:.*|URL\(s\) of infringing content:.*`)
)

func NewParser() *Parser {
	return &Parser{}
}

// extractValue extracts the value from a "Key: Value" line
func extractValue(line string) string {
	parts := strings.SplitN(line, ": ", 2)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// parseTextFormat parses the simple text format
func parseTextFormat(body string, serializedEmail *email.SerializedEmail, trademarkOwner string) (*events.Event, error) {
	event := events.NewEvent("react")

	// Get event date from email headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		event.EventDate = email.ParseDate(dateHeader[0])
	}
	if event.EventDate == nil {
		return nil, common.NewParserError("no date found in headers")
	}

	// Find first line starting with http
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "http") {
			event.URL = strings.TrimSpace(line)
			break
		}
	}

	event.EventTypes = []events.EventType{events.NewTrademark("", nil, trademarkOwner, "")}
	return event, nil
}

// parseTextFormatAndOwner parses text format and extracts trademark owner
func parseTextFormatAndOwner(body string, serializedEmail *email.SerializedEmail) (*events.Event, error) {
	trademarkOwner := strings.TrimSpace(common.FindStringWithoutMarkers(body, "copyrighted content of", "without"))
	return parseTextFormat(body, serializedEmail, trademarkOwner)
}

// parseFakeInfringement parses fake infringement format
func parseFakeInfringement(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	owner := strings.TrimSpace(strings.Trim(common.FindStringWithoutMarkers(body, "on behalf of", "which"), ","))

	var result []*events.Event
	blockLines := common.GetBlockAround(body, "infringement causing damage")

	for _, line := range blockLines {
		if strings.HasPrefix(strings.TrimSpace(line), "http") {
			event := events.NewEvent("react")

			// Get event date from email headers
			if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
				event.EventDate = email.ParseDate(dateHeader[0])
			}

			event.URL = strings.TrimSpace(line)
			event.EventTypes = []events.EventType{events.NewTrademark("", nil, owner, "")}
			result = append(result, event)
		}
	}

	if len(result) == 0 {
		return nil, common.NewParserError("no URLs found in fake infringement format")
	}

	return result, nil
}

// createEventFromIncidentLines creates an event from incident lines
func createEventFromIncidentLines(incidentLines []string, serializedEmail *email.SerializedEmail) (*events.Event, error) {
	event := events.NewEvent("react")
	registrant := ""
	registrar := ""

	for _, line := range incidentLines {
		trimmedLine := strings.TrimSpace(line)

		if strings.HasPrefix(trimmedLine, "Date:") {
			dateFromBody := strings.TrimSpace(extractValue(trimmedLine))
			// Convert date format from YYYY-MM-DD to YYYY/MM/DD
			dateFromBody = strings.ReplaceAll(dateFromBody, "-", "/")
			event.EventDate = email.ParseDate(dateFromBody + " 00:00:00")
		} else if strings.HasPrefix(trimmedLine, "URL:") && event.URL == "" {
			event.URL = extractValue(trimmedLine)
		} else if strings.HasPrefix(trimmedLine, "Page:") {
			event.URL = extractValue(trimmedLine)
		} else if strings.HasPrefix(trimmedLine, "ISP:") {
			ispName := extractValue(trimmedLine)
			if ispName != "" {
				event.AddEventDetail(&events.ISP{ISPName: ispName, Country: ""})
			}
		} else if strings.HasPrefix(trimmedLine, "Homepage:") && event.URL == "" {
			event.URL = extractValue(trimmedLine)
		} else if strings.HasPrefix(trimmedLine, "Domain:") && event.URL == "" {
			event.URL = extractValue(trimmedLine)
		} else if strings.HasPrefix(trimmedLine, "IP nr:") {
			event.IP = extractValue(trimmedLine)
		} else if strings.HasPrefix(trimmedLine, "Registrant:") {
			val := extractValue(trimmedLine)
			if val != "" {
				registrant = val
			}
		} else if strings.HasPrefix(trimmedLine, "Registrar:") {
			val := extractValue(trimmedLine)
			if val != "" {
				registrar = val
			}
		} else if strings.HasPrefix(trimmedLine, "Brand:") {
			brand := extractValue(trimmedLine)
			if brand != "" {
				event.AddEventDetail(&events.Target{Brand: brand})
			}
		}
	}

	// Fallback to email header date if not found in body
	if event.EventDate == nil {
		if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
			event.EventDate = email.ParseDate(dateHeader[0])
		}
	}

	// Build trademark owner from registrant and registrar
	trademarkOwner := ""
	if registrant != "" || registrar != "" {
		parts := []string{}
		if registrant != "" {
			parts = append(parts, registrant)
		}
		if registrar != "" {
			parts = append(parts, registrar)
		}
		trademarkOwner = strings.Join(parts, ", ")
	}

	event.EventTypes = []events.EventType{events.NewTrademark("", nil, trademarkOwner, "")}

	return event, nil
}

// parseListedFormatForURLs parses listed format with multiple URLs
func parseListedFormatForURLs(body string, serializedEmail *email.SerializedEmail, urls []string) ([]*events.Event, error) {
	var result []*events.Event

	for _, url := range urls {
		incidentLines := common.GetBlockAround(body, strings.TrimSpace(url))

		// If first line is "URL:", pop it and prepend to each line
		if len(incidentLines) > 0 && strings.TrimSpace(incidentLines[0]) == "URL:" {
			incidentLines = incidentLines[1:]
			for i, line := range incidentLines {
				incidentLines[i] = "URL: " + line
			}
		}

		event, err := createEventFromIncidentLines(incidentLines, serializedEmail)
		if err != nil {
			continue
		}
		result = append(result, event)
	}

	if len(result) == 0 {
		return nil, common.NewParserError("no events created from listed format")
	}

	return result, nil
}

// extractIncidentLines extracts incident lines from body
func extractIncidentLines(body string) []string {
	var incidentLines []string
	appendLines := false

	lines := strings.Split(body, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Date:") || strings.Contains(line, "URL:") {
			if !appendLines {
				appendLines = true
			}
		}

		if appendLines {
			incidentLines = append(incidentLines, line)
		}

		// Stop at empty line after we started appending
		if appendLines && strings.TrimSpace(line) == "" {
			break
		}
	}

	return incidentLines
}

// parseListedFormat parses listed format
func parseListedFormat(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	incidentLines := extractIncidentLines(body)
	event, err := createEventFromIncidentLines(incidentLines, serializedEmail)
	if err != nil {
		return nil, err
	}
	return []*events.Event{event}, nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Find all URL patterns
	urls := urlPattern.FindAllString(body, -1)

	// Route to appropriate parser based on subject
	if strings.Contains(subject, "Infringement") && len(urls) >= 1 {
		return parseListedFormatForURLs(body, serializedEmail, urls)
	} else if strings.Contains(subject, "Case:") && len(urls) >= 1 {
		return parseListedFormatForURLs(body, serializedEmail, urls)
	} else if strings.Contains(subject, "Website") {
		event, err := parseTextFormat(body, serializedEmail, "")
		if err != nil {
			return nil, err
		}
		return []*events.Event{event}, nil
	} else if strings.Contains(subject, "fake Infringement") {
		return parseFakeInfringement(body, serializedEmail)
	} else if strings.Contains(subject, "copyright Infringement") {
		event, err := parseTextFormatAndOwner(body, serializedEmail)
		if err != nil {
			return nil, err
		}
		return []*events.Event{event}, nil
	} else {
		return parseListedFormat(body, serializedEmail)
	}
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
