// Package ephemeron implements the ephemeron parser
package ephemeron

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the ephemeron parser
type Parser struct{}

var regexPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?P<date>.*)delta.*from (?P<ip>\d{1,4}\.\d{1,4}\.\d{1,4}\.\d{1,4}) port (?P<port>\d+) ssh`),
	regexp.MustCompile(`(?P<date>.*) ephemeron.*from (?P<ip>\d{1,4}\.\d{1,4}\.\d{1,4}\.\d{1,4})`),
	regexp.MustCompile(`(?P<date>.*) (delta|charlie).*Invalid user (?P<username>.*) from (?P<ip>\d{1,4}\.\d{1,4}\.\d{1,4}\.\d{1,4})`),
	regexp.MustCompile(`(?P<date>.*) ephemeron.*user=<(?P<username>.*)>.*rip=(?P<ip>\d{1,4}\.\d{1,4}\.\d{1,4}\.\d{1,4}).*lip=(?P<dst_ip>\d{1,4}\.\d{1,4}\.\d{1,4}\.\d{1,4})`),
}

// stripHTML removes HTML tags from a string
func stripHTML(s string) string {
	tagRe := regexp.MustCompile(`<[^>]*>`)
	return tagRe.ReplaceAllString(s, "")
}

// parseLoginAttack parses login attack events from logs
func parseLoginAttack(logs string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	var year string
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		parsedDate := email.ParseDate(dateHeaders[0])
		if parsedDate != nil {
			year = fmt.Sprintf("%d", parsedDate.Year())
		}
	}

	// Find matching regex
	var matchedRegex *regexp.Regexp
	for _, regex := range regexPatterns {
		if regex.MatchString(logs) {
			matchedRegex = regex
			break
		}
	}

	if matchedRegex == nil {
		return nil, common.NewParserError("no regex matched, adapt the parser")
	}

	ipPortCombinations := make(map[string]bool)
	var result []*events.Event

	lines := strings.Split(logs, "\n")
	for _, line := range lines {
		matches := matchedRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		names := matchedRegex.SubexpNames()
		groups := make(map[string]string)
		for i, name := range names {
			if i > 0 && i < len(matches) {
				groups[name] = matches[i]
			}
		}

		dateStr := groups["date"]
		ip := groups["ip"]
		port := groups["port"]
		username := groups["username"]
		dstIP := groups["dst_ip"]

		combination := fmt.Sprintf("%s-%s", ip, port)
		if ipPortCombinations[combination] {
			continue
		}
		ipPortCombinations[combination] = true

		// Parse date: "Month Day Time"
		parts := strings.Fields(dateStr)
		var month, day, timeStr string
		for _, part := range parts {
			if part != "" {
				if month == "" {
					month = part
				} else if day == "" {
					day = part
				} else if timeStr == "" {
					timeStr = part
					break
				}
			}
		}

		dateFormatted := fmt.Sprintf("%s-%s-%s %s", year, month, day, timeStr)

		event := events.NewEvent("ephemeron")
		event.EventDate = email.ParseDate(dateFormatted)
		loginAttack := events.NewLoginAttack(username, "")
		event.EventTypes = []events.EventType{loginAttack}
		event.IP = ip
		if port != "" {
			if portInt, err := strconv.Atoi(port); err == nil {
				event.Port = portInt
			}
		}
		if dstIP != "" {
			target := &events.Target{IP: dstIP}
			event.AddEventDetail(target)
		}
		result = append(result, event)
	}

	return result, nil
}

// Parse parses emails from @ephemeron.org
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	if len(serializedEmail.Parts) < 3 {
		return nil, common.NewParserError(fmt.Sprintf("expected at least 3 parts, got %d", len(serializedEmail.Parts)))
	}

	report := serializedEmail.Parts[1]
	messagePart := serializedEmail.Parts[2]

	var reportBody string
	if body, ok := report.Body.(string); ok {
		reportBody = body
	} else if bodyBytes, ok := report.Body.([]byte); ok {
		reportBody = string(bodyBytes)
	}

	var message string
	if body, ok := messagePart.Body.(string); ok {
		message = strings.ToLower(body)
	} else if bodyBytes, ok := messagePart.Body.([]byte); ok {
		message = strings.ToLower(string(bodyBytes))
	}

	if reportBody != "" && (strings.Contains(reportBody, "ssh") || strings.Contains(reportBody, "auth")) {
		return parseLoginAttack(reportBody, serializedEmail)
	}

	// Parse spam report
	var url string
	if strings.Contains(message, "<html") || strings.Contains(message, "<head") {
		message = stripHTML(message)
	}

	urlRegex := regexp.MustCompile(`(http\S*)`)
	if matches := urlRegex.FindStringSubmatch(message); len(matches) > 0 {
		url = matches[1]
	}

	event := events.NewEvent("ephemeron")

	// Get source IP from report headers
	if sourceIP, ok := report.Headers["source-ip"]; ok && len(sourceIP) > 0 {
		event.IP = sourceIP[0]
	}

	event.URL = url

	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Check feedback type
	if feedbackType, ok := report.Headers["feedback-type"]; ok && len(feedbackType) > 0 {
		if strings.Contains(feedbackType[0], "spam") {
			event.EventTypes = []events.EventType{events.NewSpam()}
		}
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
