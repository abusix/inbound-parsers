// Package zerofox implements the ZeroFox parser for security reports
package zerofox

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the ZeroFox parser
type Parser struct{}

// Parse parses ZeroFox security reports
// Handles malicious activity, phishing, scam, fraud, and DMCA reports
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Get date fallback from headers
	var dateFallback *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		dateFallback = email.ParseDate(dateHeader[0])
	}

	subjectLower := strings.ToLower(subject)

	// Route to appropriate parser based on subject
	if containsAny(subjectLower, []string{"malicious activity", "suspicious traffic", "malicious traffic"}) {
		return parseMalicious(body, dateFallback)
	} else if containsAny(subjectLower, []string{"phishing", "phish", "scam", "fraudulent"}) {
		return parsePhishingScam(body, dateFallback, subjectLower)
	} else if strings.Contains(subjectLower, "dmca") {
		return parseDMCA(body, dateFallback)
	} else if strings.Contains(subjectLower, "fraud") {
		return parseFraud(body, dateFallback)
	}

	return nil, common.NewNewTypeError(subjectLower)
}

// parseMalicious parses malicious activity reports (DDoS, malicious activity)
func parseMalicious(body string, dateFallback *time.Time) ([]*events.Event, error) {
	bodyLower := strings.ToLower(strings.ReplaceAll(body, ">", ""))

	var eventTemplate *events.Event
	eventTemplate = events.NewEvent("zerofox")
	eventTemplate.EventDate = dateFallback

	// Determine event type based on content
	if containsAny(bodyLower, []string{"denial of service attack", "ddos"}) {
		eventTemplate.EventTypes = []events.EventType{events.NewDDoS()}
	} else {
		eventTemplate.EventTypes = []events.EventType{events.NewMaliciousActivity()}
	}

	// Look for on-behalf-of information
	for _, marker := range []string{"zerofox represents", "we represent"} {
		if behalf := common.FindStringWithoutMarkers(bodyLower, marker, "and"); behalf != "" {
			eventTemplate.AddEventDetail(&events.OnBehalfOf{
				ComplainantContact: behalf,
			})
			break
		}
	}

	var eventsList []*events.Event
	foundIP := false

	// Look for IP addresses in various locations
	for _, marker := range []string{"following ips:", "customer service:", "on their servers:"} {
		if strings.Contains(bodyLower, marker) {
			block := common.GetBlockAfter(bodyLower, marker)
			for _, line := range block {
				// Try to extract IP from line
				if ipAddr := common.ExtractOneIP(line); ipAddr != "" {
					event := copyEvent(eventTemplate)
					event.IP = ipAddr
					eventsList = append(eventsList, event)
					foundIP = true
				}
			}
			if foundIP {
				break
			}
		}
	}

	// If no IPs found yet, try "ip:" marker
	if !foundIP {
		if strings.Contains(bodyLower, "ip:") {
			if ipAddr := common.FindStringWithoutMarkers(bodyLower, "ip:", ""); ipAddr != "" {
				// Validate and extract IP
				if validIP := common.ExtractOneIP(ipAddr); validIP != "" {
					eventTemplate.IP = validIP
					eventsList = append(eventsList, eventTemplate)
					foundIP = true
				}
			}
		}
	}

	if !foundIP {
		return nil, common.NewParserError("No IP found")
	}

	return eventsList, nil
}

// parsePhishingScam parses phishing and scam reports
func parsePhishingScam(body string, dateFallback *time.Time, subjectLower string) ([]*events.Event, error) {
	event := events.NewEvent("zerofox")
	event.EventDate = dateFallback

	var url string

	// Extract URL based on type
	if strings.Contains(subjectLower, "webphish") || strings.Contains(subjectLower, "web phish") {
		// Look for URL with regex pattern
		re := regexp.MustCompile(`(?i)(URL:)[^h.]*([^}\s]+)`)
		if match := re.FindStringSubmatch(body); len(match) >= 3 {
			url = match[2]
			event.URL = url
		}
	} else {
		// Standard URL extraction
		if foundURL := common.FindStringWithoutMarkers(body, "URL:", ""); foundURL != "" {
			url = foundURL
			event.URL = url
		}
	}

	// If no URL found, try to find IP
	if event.URL == "" {
		bodyLower := strings.ToLower(body)
		if strings.Contains(bodyLower, "ip address") {
			if ipLine := common.GetNonEmptyLineAfter(bodyLower, "ip address"); ipLine != "" {
				if validIP := common.ExtractOneIP(ipLine); validIP != "" {
					event.IP = validIP
				} else {
					return nil, common.NewParserError("No URL or IP found")
				}
			} else {
				return nil, common.NewParserError("No URL or IP found")
			}
		} else {
			// Try using subject as IP
			if validIP := common.ExtractOneIP(subjectLower); validIP != "" {
				event.IP = validIP
			} else {
				return nil, common.NewParserError("No IP found")
			}
		}
	}

	// Determine event type
	if strings.Contains(strings.ToLower(body), "scam") || strings.Contains(subjectLower, "fraudulent") {
		event.EventTypes = []events.EventType{events.NewFraud()}
	} else {
		phishing := events.NewPhishing()
		if url != "" {
			phishing.PhishingTarget = url
		}
		event.EventTypes = []events.EventType{phishing}
	}

	return []*events.Event{event}, nil
}

// parseFraud parses fraud reports
func parseFraud(body string, dateFallback *time.Time) ([]*events.Event, error) {
	event := events.NewEvent("zerofox")
	event.EventDate = dateFallback

	bodyLower := strings.ToLower(body)
	if urlStr := common.GetNonEmptyLineAfter(bodyLower, "network:"); urlStr != "" {
		event.URL = urlStr
	}

	event.EventTypes = []events.EventType{events.NewFraud()}
	return []*events.Event{event}, nil
}

// parseDMCA parses DMCA copyright reports
func parseDMCA(body string, dateFallback *time.Time) ([]*events.Event, error) {
	event := events.NewEvent("zerofox")

	var copyrightedWork string

	// Extract copyrighted work
	workRe := regexp.MustCompile(`(?i)(original work.*\s*.*)\s*(?P<url>.*)`)
	if workMatch := workRe.FindStringSubmatch(body); len(workMatch) >= 3 {
		copyrightedWork = strings.Trim(workMatch[2], "[]")
	}

	event.EventTypes = []events.EventType{
		events.NewCopyright(copyrightedWork, "", ""),
	}

	// Extract infringing URL
	urlRe := regexp.MustCompile(`(?i)(allegedly infringing content.*\s*.*)\s*(?P<url>.*)`)
	if urlMatch := urlRe.FindStringSubmatch(body); len(urlMatch) >= 3 {
		event.URL = strings.Trim(urlMatch[2], "[]")
	}

	event.EventDate = dateFallback
	return []*events.Event{event}, nil
}

// containsAny checks if a string contains any of the given substrings
func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// copyEvent creates a deep copy of an event (for template reuse)
func copyEvent(src *events.Event) *events.Event {
	dst := events.NewEvent(src.Parser)
	dst.EventDate = src.EventDate
	dst.EventTypes = make([]events.EventType, len(src.EventTypes))
	copy(dst.EventTypes, src.EventTypes)

	// Copy event details
	if len(src.EventDetails) > 0 {
		dst.EventDetails = make([]events.EventDetail, len(src.EventDetails))
		copy(dst.EventDetails, src.EventDetails)
	}

	return dst
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
