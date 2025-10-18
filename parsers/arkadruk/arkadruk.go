package arkadruk

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	// IP patterns matching Python implementation
	ipPattern1 = regexp.MustCompile(`(?i)((IP)?\s*)\s*(\[?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\]?|\[\s\d{0,3}\s\.\s\d{0,3}\s\.\s\d{0,3}\s\.\s\d{0,3}\s\])`)
	ipPattern2 = regexp.MustCompile(`(?i)(IP)(\[?\s\d{0,3}\s\.\s\d{0,3}\s\.\s\d{0,3}\s\.\s\d{0,3}\s\]?)`)
	urlPattern = regexp.MustCompile(`(?i)(It contained urls:\s*)\s*(http.*)`)
)

func NewParser() *Parser {
	return &Parser{}
}

// parseSpoof handles IP spoofing reports
func parseSpoof(body string, eventDate *time.Time) ([]*events.Event, error) {
	event := events.NewEvent("arkadruk")
	event.EventDate = eventDate
	event.EventTypes = []events.EventType{events.NewIPSpoof("", "", false, "")}

	// Extract IP using pattern
	if match := ipPattern1.FindStringSubmatch(body); match != nil && len(match) > 3 {
		ipStr := match[3]
		ipStr = strings.ReplaceAll(ipStr, "[.]", ".")
		ipStr = strings.ReplaceAll(ipStr, "[", "")
		ipStr = strings.ReplaceAll(ipStr, "]", "")
		ipStr = strings.ReplaceAll(ipStr, " ", "")
		ipStr = strings.TrimSpace(ipStr)

		if ip := common.IsIP(ipStr); ip != "" {
			event.IP = ip
			return []*events.Event{event}, nil
		}
	}

	return nil, common.NewParserError("couldn't find IP")
}

// parseMalicious handles malicious activity reports
func parseMalicious(body string, eventDate *time.Time) ([]*events.Event, error) {
	event := events.NewEvent("arkadruk")
	event.EventDate = eventDate
	event.EventTypes = []events.EventType{events.NewMaliciousActivity()}

	// Try first IP pattern
	if match := ipPattern1.FindStringSubmatch(body); match != nil && len(match) > 3 {
		ipStr := match[3]
		ipStr = strings.ReplaceAll(ipStr, "[.]", ".")
		ipStr = strings.ReplaceAll(ipStr, "[", "")
		ipStr = strings.ReplaceAll(ipStr, "]", "")
		ipStr = strings.ReplaceAll(ipStr, " ", "")
		ipStr = strings.TrimSpace(ipStr)

		if ip := common.IsIP(ipStr); ip != "" {
			event.IP = ip
		}
	}

	// If no IP found, try second pattern
	if event.IP == "" {
		if match := ipPattern2.FindStringSubmatch(body); match != nil && len(match) > 2 {
			ipStr := match[2]
			ipStr = strings.ReplaceAll(ipStr, "[.]", ".")
			ipStr = strings.ReplaceAll(ipStr, "[", "")
			ipStr = strings.ReplaceAll(ipStr, "]", "")
			ipStr = strings.ReplaceAll(ipStr, " ", "")
			ipStr = strings.TrimSpace(ipStr)

			if ip := common.IsIP(ipStr); ip != "" {
				event.IP = ip
			}
		}
	}

	// Try to extract URL
	if match := urlPattern.FindStringSubmatch(body); match != nil && len(match) > 2 {
		urlStr := strings.ReplaceAll(match[2], " ", "")
		event.URL = strings.TrimSpace(urlStr)
	}

	// If still no IP or URL, try extracting from "Received :" headers
	if event.IP == "" && event.URL == "" {
		bodyLower := strings.ToLower(body)
		receivedParts := strings.Split(bodyLower, "received :")

		if len(receivedParts) > 0 {
			importantHeaders := []string{receivedParts[len(receivedParts)-1]}
			if len(receivedParts) > 2 {
				importantHeaders = append(importantHeaders, receivedParts[len(receivedParts)-2])
			}

			for _, header := range importantHeaders {
				header = strings.ReplaceAll(header, " ", "")
				if ip := common.ExtractOneIP(header); ip != "" {
					event.IP = ip
					break
				}
			}
		}
	}

	// Must have either IP or URL
	if event.IP != "" || event.URL != "" {
		return []*events.Event{event}, nil
	}

	return nil, common.NewParserError("couldn't find URL or IP")
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, _ := common.GetSubject(serializedEmail, false)

	// Strip HTML if present
	if strings.Contains(body, "<html>") {
		body = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(body, " ")
	}

	// Get date from headers as fallback
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	// Determine event type based on subject
	subjectLower := strings.ToLower(subject)
	if strings.Contains(subjectLower, "spoof") {
		return parseSpoof(body, eventDate)
	} else if strings.Contains(subjectLower, "suspicious") ||
		strings.Contains(subjectLower, "problem with") ||
		strings.Contains(subjectLower, "remove from") {
		return parseMalicious(body, eventDate)
	}

	return nil, common.NewParserError("unknown subject type: " + subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
