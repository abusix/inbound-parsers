// Package spamcop implements the SpamCop parser
package spamcop

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the SpamCop parser
type Parser struct{}

var (
	// W3M_PATTERN = re.compile(r'h..ps?://www.spamcop.net/w3m\?i=.*?\n')
	w3mPattern = regexp.MustCompile(`h..ps?://www\.spamcop\.net/w3m\?i=.*?\n`)

	// SPAMVERTIZED_PATTERN with named groups
	spamvertizedPattern = regexp.MustCompile(
		`Spamvertised web site:\s+(?P<url>.*?)(?P<w3m>\shttps://www\.spamcop\.net/w3m.*?\s).*?\s+` +
			`is\s+(?P<ip>[.\d]{7,15});\s+(?P<date>[\w,.:\d\- ]*)`,
	)

	// SPAMVERTIZED_PATTERN_SIMPLE
	spamvertizedPatternSimple = regexp.MustCompile(`Spamvertised web site:\s+(?P<url>.*)\s(?P<w3m>.*)`)

	// Date pattern for extracting oldest date
	oldestDatePattern = regexp.MustCompile(`[a-z]{2,4}, \d{1,2} [a-z]{3,4} \d{4} [\d|:]* \S+`)
)

// NewParser creates a new SpamCop parser
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses a SpamCop email
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	fromAddr, _ := common.GetFrom(serializedEmail, false)

	// First check if body contains only IPs (blacklist format)
	ips, isBlacklist := onlyIPs(body)
	if isBlacklist {
		var eventsList []*events.Event
		oldestDate := extractOldestDate(serializedEmail, body)
		for _, ip := range ips {
			event := events.NewEvent("spamcop")
			event.IP = ip
			event.EventDate = oldestDate
			event.EventTypes = []events.EventType{events.NewBlacklist("")}
			eventsList = append(eventsList, event)
		}
		return eventsList, nil
	}

	var eventsList []*events.Event

	// Parse based on sender domain
	if strings.HasSuffix(fromAddr, "admin.spamcop.net") {
		eventsList, err = parseAdmin(serializedEmail, fromAddr)
		if err != nil {
			return nil, err
		}
	} else if strings.HasSuffix(fromAddr, "reports.spamcop.net") || strings.HasSuffix(fromAddr, "myloc.de") {
		eventsList, err = parseReports(serializedEmail, fromAddr)
		if err != nil {
			return nil, err
		}
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no event created")
	}

	// Add evidence headers to all events
	addEvidenceHeaders(eventsList, serializedEmail)

	return eventsList, nil
}

// onlyIPs checks if body contains only IP addresses (one per line)
func onlyIPs(body string) ([]string, bool) {
	var ips []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		ip := common.IsIP(common.ExtractOneIP(line))
		if ip == "" {
			return nil, false
		}
		ips = append(ips, ip)
	}
	return ips, len(ips) > 0
}

// parseAdmin parses emails from admin.spamcop.net
func parseAdmin(serializedEmail *email.SerializedEmail, fromAddr string) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	body = strings.ReplaceAll(body, "\r", "")

	var eventsList []*events.Event
	delimiter := "\n--"
	startIndex := strings.Index(body, delimiter)
	if startIndex == -1 {
		return parseAdminAlternate(serializedEmail, fromAddr, body)
	}

	startIndex += len(delimiter)
	endIndex := strings.Index(body[startIndex:], delimiter)

	date := extractOldestDate(serializedEmail, body)
	if endIndex > 0 {
		section := body[startIndex : startIndex+endIndex]
		section = strings.TrimSpace(section)

		for _, line := range strings.Split(section, "\n") {
			event := createEvent(line, date.Year(), fromAddr)
			if event != nil {
				eventsList = append(eventsList, event)
			}
		}
	}

	// Check for IPs section
	if strings.Contains(body, "IPs") {
		startIndex := strings.Index(body, "IPs")
		endIndex := strings.Index(body[startIndex:], ":\n")
		if endIndex != -1 {
			section := body[startIndex+endIndex+2:]
			section = strings.TrimSpace(section)

			for _, line := range strings.Split(section, "\n") {
				line = strings.TrimSpace(line)
				ip := common.IsIP(line)
				if ip != "" {
					event := getEventWithCommonParts(fromAddr)
					event.IP = ip
					event.EventTypes = []events.EventType{events.NewSpam()}
					event.EventDate = date
					eventsList = append(eventsList, event)
				}
			}
		}
	}

	if len(eventsList) == 0 {
		return parseAdminAlternate(serializedEmail, fromAddr, body)
	}

	return eventsList, nil
}

// parseAdminAlternate handles alternate admin email formats
func parseAdminAlternate(serializedEmail *email.SerializedEmail, fromAddr, body string) ([]*events.Event, error) {
	var eventsList []*events.Event

	// Check for parts format
	if len(serializedEmail.Parts) >= 2 {
		summaryBody, ok := serializedEmail.Parts[1].Body.(string)
		if !ok {
			if bodyBytes, ok := serializedEmail.Parts[1].Body.([]byte); ok {
				summaryBody = string(bodyBytes)
			} else {
				return parseAdminSummary(serializedEmail, fromAddr, body)
			}
		}

		summary := common.GetNonEmptyLineAfter(summaryBody, "Summary:")
		if summary == "" {
			return parseAdminSummary(serializedEmail, fromAddr, body)
		}

		parts := strings.SplitN(summary, " ", 2)
		if len(parts) < 2 {
			return nil, common.NewParserError("failed to parse summary line")
		}

		ip := parts[0]
		dateStr := strings.TrimSpace(parts[1])
		dateParts := strings.Split(dateStr, "/")
		if len(dateParts) == 0 {
			return nil, common.NewParserError("failed to parse date")
		}
		dateStr = dateParts[0]

		// Get year from date header
		var year int
		if dateHeader, ok := serializedEmail.Parts[1].Headers["date"]; ok && len(dateHeader) > 0 {
			if t := email.ParseDate(dateHeader[0]); t != nil {
				year = t.Year()
			}
		}

		timeParts := strings.Fields(dateStr)
		if len(timeParts) < 3 {
			return nil, common.NewParserError("failed to parse date fields")
		}

		month := timeParts[0]
		day := timeParts[1]
		hour := strings.TrimSuffix(timeParts[2], "h")

		dateTimeStr := fmt.Sprintf("%s %s %d %s:00:00", day, month, year, hour)
		datetime := parseMagicDateTime(dateTimeStr)

		event := events.NewEvent("spamcop")
		event.IP = ip
		event.EventDate = datetime
		event.EventTypes = []events.EventType{events.NewSpam()}
		eventsList = append(eventsList, event)
		return eventsList, nil
	}

	return parseAdminSummary(serializedEmail, fromAddr, body)
}

// parseAdminSummary handles the summary format
func parseAdminSummary(serializedEmail *email.SerializedEmail, fromAddr, body string) ([]*events.Event, error) {
	timeOfReportStr := common.FindStringWithoutMarkers(body, "Time of this report is:", "")
	if timeOfReportStr == "" {
		return nil, common.NewParserError("time of report not found")
	}

	timeOfReport := parseMagicDateTime(timeOfReportStr)
	if timeOfReport == nil {
		return nil, common.NewParserError("failed to parse time of report")
	}

	summaryParts := strings.Split(body, "Summary:")
	if len(summaryParts) < 2 {
		return nil, common.NewParserError("summary section not found")
	}

	summary := strings.TrimSpace(summaryParts[1])
	var eventsList []*events.Event
	var ip, rdns string
	var eventDate *time.Time

	for _, line := range strings.Split(summary, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if ip == "" {
			// Parse IP and date line
			parts := strings.SplitN(line, " ", 2)
			if len(parts) < 2 {
				continue
			}

			ip = parts[0]
			datePart := strings.TrimSpace(parts[1])
			dateFields := strings.Fields(datePart)
			if len(dateFields) < 3 {
				continue
			}

			month := dateFields[0]
			day := dateFields[1]
			hourStr := strings.TrimSuffix(dateFields[2], "h")
			year := timeOfReport.Year()

			dateStr := fmt.Sprintf("%s %s %d %s:00:00", day, month, year, hourStr)
			date := parseMagicDateTime(dateStr)

			// Check if date is in future
			if date != nil && date.After(*timeOfReport) {
				year--
				dateStr = fmt.Sprintf("%s %s %d %s:00:00", day, month, year, hourStr)
				date = parseMagicDateTime(dateStr)
			}

			eventDate = date
		} else {
			// Parse rdns line
			rdns = strings.TrimSuffix(strings.Fields(line)[0], ".")
			event := events.NewEvent("spamcop")
			event.IP = ip
			event.EventDate = eventDate
			event.URL = rdns
			event.EventTypes = []events.EventType{events.NewSpam()}
			eventsList = append(eventsList, event)
			ip = ""
			rdns = ""
		}
	}

	return eventsList, nil
}

// createEvent creates an event from a log line
func createEvent(line string, year int, fromAddr string) *events.Event {
	line = strings.TrimSpace(line)
	// Normalize whitespace
	line = strings.Join(strings.Fields(line), " ")

	parts := strings.Fields(line)
	if len(parts) < 4 {
		return nil
	}

	month := parts[1]
	day := parts[2]
	hourParts := strings.Split(parts[3], "h")
	if len(hourParts) == 0 {
		return nil
	}
	hour := hourParts[0]

	event := getEventWithCommonParts(fromAddr)
	ip := common.ExtractOneIP(line)
	ip = common.IsIP(ip)
	if ip == "" {
		return nil
	}
	event.IP = ip
	event.EventTypes = []events.EventType{events.NewSpam()}

	dateStr := fmt.Sprintf("%s %s %d %s:00:00", month, day, year, hour)
	event.EventDate = parseMagicDateTime(dateStr)
	if event.EventDate == nil {
		return nil
	}

	return event
}

// parseReports parses emails from reports.spamcop.net
func parseReports(serializedEmail *email.SerializedEmail, fromAddr string) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)

	// Convert bytes to string if needed
	if bodyBytes, ok := serializedEmail.Body.([]byte); ok {
		body = string(bodyBytes)
	}

	spamvertised := false
	if strings.Contains(body, "Spamvertised web site: ") {
		spamvertised = true
	} else if len(serializedEmail.Parts) > 0 {
		if partBody, ok := serializedEmail.Parts[0].Body.(string); ok {
			if strings.Contains(partBody, "Spamvertised web site: ") {
				spamvertised = true
				body = partBody
			}
		}
	}

	var eventsList []*events.Event

	if spamvertised {
		// Try full pattern first
		matches := spamvertizedPattern.FindAllStringSubmatch(body, -1)
		if len(matches) > 0 {
			for _, match := range matches {
				if len(match) < 5 {
					continue
				}
				event := getEventWithCommonParts(fromAddr)
				event.EventTypes = []events.EventType{events.NewSpamvertised()}

				// Extract named groups
				url := strings.TrimSpace(match[1])
				w3m := strings.TrimSpace(match[2])
				ip := strings.TrimSpace(match[3])
				dateStr := strings.TrimSpace(match[4])

				event.URL = url
				event.IP = ip
				event.EventDate = parseMagicDateTime(dateStr)

				if w3m != "" {
					evidence := &events.Evidence{}
					evidence.AddEvidence(events.UrlStore{URL: w3m})
					event.AddEventDetail(evidence)
				}

				eventsList = append(eventsList, event)
			}
		} else {
			// Try simple pattern
			data := common.FindStringWithoutMarkers(body, "received from IP source", "")
			parts := strings.SplitN(data, " on ", 2)
			var ip, dateStr string
			if len(parts) == 2 {
				ip = strings.TrimSpace(parts[0])
				dateStr = strings.TrimSpace(parts[1])
			}

			matches := spamvertizedPatternSimple.FindAllStringSubmatch(body, -1)
			for _, match := range matches {
				if len(match) < 3 {
					continue
				}

				event := getEventWithCommonParts(fromAddr)
				event.EventTypes = []events.EventType{events.NewSpamvertised()}

				url := strings.TrimSpace(match[1])
				w3m := strings.TrimSpace(match[2])

				var eventDate *time.Time
				if dateStr != "" {
					eventDate = parseMagicDateTime(dateStr)
				} else {
					eventDate = extractOldestDate(serializedEmail, body)
				}
				event.EventDate = eventDate

				event.IP = ip
				if common.IsIP(event.IP) == "" {
					if url == "" {
						return nil, common.NewParserError("no url and no ip provided")
					}
				}

				if w3m != "" {
					evidence := &events.Evidence{}
					evidence.AddEvidence(events.UrlStore{URL: w3m})
					event.AddEventDetail(evidence)
				}

				event.URL = url
				eventsList = append(eventsList, event)
			}
		}
		return eventsList, nil
	}

	// Regular spam report
	event := getEventWithCommonParts(fromAddr)

	// Try to get IP from x-spamcop-sourceip header
	var ip string
	if sourceIP, ok := serializedEmail.Headers["x-spamcop-sourceip"]; ok && len(sourceIP) > 0 {
		ip = common.ExtractOneIP(sourceIP[0])
		ip = common.IsIP(ip)
	}

	// If not found, try subject
	if ip == "" {
		subject, _ := common.GetSubject(serializedEmail, false)
		ip = common.ExtractOneIP(subject)
		ip = common.IsIP(ip)
	}

	// If still not found, try body
	if ip == "" {
		ipStr := common.FindStringWithoutMarkers(body, "Email from", "/")
		ip = common.IsIP(ipStr)
	}

	if ip == "" {
		return nil, common.NewParserError("no IP found")
	}

	event.EventTypes = []events.EventType{events.NewSpam()}
	event.IP = ip
	event.EventDate = extractOldestDate(serializedEmail, body)

	// Look for w3m URL
	w3mMatch := w3mPattern.FindString(body)
	if w3mMatch != "" {
		w3mURL := strings.TrimSpace(w3mMatch)
		evidence := &events.Evidence{}
		evidence.AddEvidence(events.UrlStore{URL: w3mURL})
		event.AddEventDetail(evidence)
	}

	return []*events.Event{event}, nil
}

// getEventWithCommonParts creates a new event with common fields
func getEventWithCommonParts(fromAddr string) *events.Event {
	event := events.NewEvent("spamcop")
	event.AddEventDetail(&events.Email{FromAddress: fromAddr})
	return event
}

// extractOldestDate extracts the oldest date from the email
func extractOldestDate(serializedEmail *email.SerializedEmail, body string) *time.Time {
	// Try to find dates in body
	bodyLower := strings.ToLower(body)
	matches := oldestDatePattern.FindAllString(bodyLower, -1)

	if len(matches) > 0 {
		oldestDate := parseMagicDateTime(matches[0])
		if oldestDate == nil {
			// Fall back to date header
			if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
				return email.ParseDate(dateHeader[0])
			}
			return nil
		}

		for _, dateStr := range matches[1:] {
			date := parseMagicDateTime(dateStr)
			if date != nil && date.Before(*oldestDate) {
				oldestDate = date
			}
		}
		return oldestDate
	}

	// Fall back to date header
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		return email.ParseDate(dateHeader[0])
	}

	return nil
}

// addEvidenceHeaders extracts and adds evidence headers from the offending message
func addEvidenceHeaders(eventsList []*events.Event, serializedEmail *email.SerializedEmail) {
	body, _ := common.GetBody(serializedEmail, false)
	if body == "" {
		return
	}

	offenderMarker := "[ Offending message ]"
	idx := strings.Index(body, offenderMarker)
	if idx == -1 {
		return
	}

	// Extract message after marker
	messageStr := body[idx+len(offenderMarker):]
	messageStr = strings.TrimLeft(messageStr, "\n\r")

	// Parse as email message
	msg, err := mail.ReadMessage(strings.NewReader(messageStr))
	if err != nil {
		return
	}

	// Extract headers
	var evidencePart []map[string]string
	for key, values := range msg.Header {
		for _, value := range values {
			if value != "" && value != "null" && value != "undefined" {
				evidencePart = append(evidencePart, map[string]string{
					"key":   key,
					"value": value,
				})
			}
		}
	}

	if len(evidencePart) == 0 {
		evidencePart = append(evidencePart, map[string]string{
			"key":   "info",
			"value": "no-evidence-data-parsed",
		})
	}

	// Add headers to all events
	for _, event := range eventsList {
		for _, entry := range evidencePart {
			key := strings.ToLower(entry["key"])
			value := entry["value"]
			if event.Headers == nil {
				event.Headers = make(map[string]interface{})
			}
			// Add to headers (append if key exists)
			if existing, ok := event.Headers[key]; ok {
				switch v := existing.(type) {
				case []interface{}:
					event.Headers[key] = append(v, value)
				case string:
					event.Headers[key] = []interface{}{v, value}
				default:
					event.Headers[key] = []interface{}{existing, value}
				}
			} else {
				event.Headers[key] = value
			}
		}
	}
}

// parseMagicDateTime attempts to parse datetime in various formats
func parseMagicDateTime(dateStr string) *time.Time {
	if dateStr == "" {
		return nil
	}

	dateStr = strings.TrimSpace(dateStr)

	// Common formats to try
	formats := []string{
		time.RFC3339,
		time.RFC1123Z,
		time.RFC1123,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02T15:04:05.999999999",
		"Jan 2 2006 15:04:05",
		"Jan 02 2006 15:04:05",
		"2 Jan 2006 15:04:05",
		"02 Jan 2006 15:04:05",
		"Mon Jan 2 15:04:05 2006",
		"Mon Jan 02 15:04:05 2006",
		"2006-01-02",
		// SpamCop specific formats
		"Mon, 2 Jan 2006 15:04:05 -0700",
		"Mon, 02 Jan 2006 15:04:05 -0700",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return &t
		}
	}

	// Try email.ParseDate for RFC 5322 formats
	if t := email.ParseDate(dateStr); t != nil {
		return t
	}

	return nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
