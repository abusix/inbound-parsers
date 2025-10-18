package hotmail

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the Hotmail parser for various hotmail.com reporters
type Parser struct{}

// Parse parses emails from various hotmail.com reporters
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Extract from address
	fromAddr := ""
	if serializedEmail.Metadata.EnvelopeFrom != "" {
		fromAddr = serializedEmail.Metadata.EnvelopeFrom
	}

	// Route to appropriate sub-parser based on sender
	if fromAddr == "staff@hotmail.com" {
		return parseStaff(serializedEmail)
	} else if fromAddr == "nicolekonopka@hotmail.com" {
		return parseNicoleKonopka(serializedEmail)
	} else if fromAddr == "ad_jensen@hotmail.com" {
		return parseAdJensen(serializedEmail)
	} else if fromAddr == "roby_burns@hotmail.com" {
		return parseRobyBurns(serializedEmail)
	} else if fromAddr == "grigory@hotmail.com" {
		return parseGrigory(serializedEmail)
	} else if fromAddr == "fidel@hotmail.co.uk" {
		return parseFidel(serializedEmail)
	} else if fromAddr == "chrisraper@hotmail.com" {
		return parseChrisRaper(serializedEmail)
	} else if fromAddr == "soniabonnefoy@hotmail.fr" {
		return parseSoniaBonnefoy(serializedEmail)
	} else if fromAddr == "klowson@hotmail.com" {
		return parseKlowson(serializedEmail)
	} else if fromAddr == "ggrotyohann@hotmail.com" {
		return parseGgrotyohann(serializedEmail)
	} else if fromAddr == "boxrain@hotmail.com" {
		return parseBoxrain(serializedEmail)
	} else if fromAddr == "bgstern19@hotmail.com" {
		return parseBgstern19(serializedEmail)
	} else if fromAddr == "tatayee@hotmail.com" {
		return parseTatayee(serializedEmail)
	} else if fromAddr == "colej2000@hotmail.com" {
		return parseColej2000(serializedEmail)
	} else if fromAddr == "blockg@hotmail.com" {
		return parseBlockg(serializedEmail)
	}

	return nil, common.NewParserError("unknown hotmail sender: " + fromAddr)
}

// parseStaff parses emails from staff@hotmail.com
func parseStaff(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	event := events.NewEvent("hotmail")
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Get event date
	eventDate, err := getDate(serializedEmail)
	if err != nil {
		return nil, err
	}
	event.EventDate = eventDate

	// Process parts
	if len(serializedEmail.Parts) == 1 {
		// Add headers from the only part
		if serializedEmail.Parts[0].Headers != nil {
			for key, values := range serializedEmail.Parts[0].Headers {
				for _, value := range values {
					addHeader(event, key, value)
				}
			}
		}
		setIP(event, serializedEmail)
		return []*events.Event{event}, nil
	}

	// Multiple parts - look for attachments
	for _, part := range serializedEmail.Parts {
		if part.Headers != nil {
			if disposition, ok := part.Headers["content-disposition"]; ok {
				for _, disp := range disposition {
					if strings.Contains(disp, "attachment") {
						for key, values := range part.Headers {
							for _, value := range values {
								addHeader(event, key, value)
							}
						}
					} else if disp == "inline" {
						for key, values := range serializedEmail.Headers {
							for _, value := range values {
								addHeader(event, key, value)
							}
						}
					}
				}
			}
		}
	}
	setIP(event, serializedEmail)
	return []*events.Event{event}, nil
}

// parseNicoleKonopka parses emails from nicolekonopka@hotmail.com
func parseNicoleKonopka(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("no body found")
	}

	parts := strings.Split(body, "Subject: ")
	if len(parts) < 2 {
		return nil, common.NewParserError("no Subject: marker found")
	}
	spamPart := parts[len(parts)-1]

	// Extract URL
	re := regexp.MustCompile(`[^\[]http[^>|\s]*`)
	match := re.FindString(spamPart)
	if match == "" {
		return nil, common.NewParserError("no url found")
	}

	url := common.CleanURL(strings.Trim(match, "<> "))

	event := events.NewEvent("hotmail")
	if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
		event.EventDate = email.ParseDate(dates[0])
	}
	event.EventTypes = []events.EventType{events.NewSpam()}
	event.URL = url

	return []*events.Event{event}, nil
}

// parseAdJensen parses emails from ad_jensen@hotmail.com
func parseAdJensen(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("no body found")
	}
	bodyLower := strings.ToLower(body)

	event := events.NewEvent("hotmail")

	var ip, url string
	if strings.Contains(bodyLower, "spam source:") {
		ip = common.GetNonEmptyLineAfter(bodyLower, "spam source:")
		url = common.GetNonEmptyLineAfter(bodyLower, "spam url:")
		event.EventTypes = []events.EventType{events.NewSpam()}
	} else if strings.Contains(bodyLower, "phishing") {
		ip = common.GetNonEmptyLineAfter(bodyLower, "fraud source:")
		url = common.GetNonEmptyLineAfter(bodyLower, "phishing url:")
		event.EventTypes = []events.EventType{events.NewPhishing()}
	} else if strings.Contains(bodyLower, "fraud") {
		ip = common.GetNonEmptyLineAfter(bodyLower, "fraud source:")
		url = common.GetNonEmptyLineAfter(bodyLower, "fraud url:")
		event.EventTypes = []events.EventType{events.NewFraud()}
	} else {
		return nil, common.NewNewTypeError("unknown type in body")
	}

	event.IP = ip
	event.URL = url
	if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
		event.EventDate = email.ParseDate(dates[0])
	}

	return []*events.Event{event}, nil
}

// parseRobyBurns parses emails from roby_burns@hotmail.com
func parseRobyBurns(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("no body found")
	}
	bodyLower := strings.ToLower(body)

	if !strings.Contains(bodyLower, "spam") {
		return nil, common.NewNewTypeError("no spam keyword")
	}

	event := events.NewEvent("hotmail")
	event.IP = common.FindStringWithoutMarkers(bodyLower, "ip address", "")
	if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
		event.EventDate = email.ParseDate(dates[0])
	}
	event.EventTypes = []events.EventType{events.NewSpam()}

	return []*events.Event{event}, nil
}

// parseGrigory parses emails from grigory@hotmail.com
func parseGrigory(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	var eventsList []*events.Event

	// Get base event date
	var eventDate *time.Time
	if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
		eventDate = email.ParseDate(dates[0])
	}

	// Find spamvertised matches
	spamvertisedRe := regexp.MustCompile(`(?i)((spamvertised|"order") link|redirect to):\s*.*\s*(?P<url>http\S+)\s*ip: (?P<ip>\S+)`)
	matches := spamvertisedRe.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) >= 4 {
			event := events.NewEvent("hotmail")
			event.EventDate = eventDate
			event.EventTypes = []events.EventType{events.NewSpamvertised()}
			event.URL = match[3] // url group
			event.IP = match[4]  // ip group
			eventsList = append(eventsList, event)
		}
	}

	// Find spam sender IP
	spamRe := regexp.MustCompile(`(?i)sender ip: (?P<ip>\S+)`)
	if match := spamRe.FindStringSubmatch(body); match != nil && len(match) >= 2 {
		event := events.NewEvent("hotmail")
		event.EventDate = eventDate
		event.EventTypes = []events.EventType{events.NewSpam()}
		event.IP = match[1]
		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

// getURL extracts URL from a line with various protocol patterns
func getURL(line string) string {
	protocols := []string{"hxxp", "hxxps", "http", "https"}
	for _, protocol := range protocols {
		if url := common.FindString(line+" ", protocol, " "); url != "" {
			return common.CleanURL(url)
		}
	}
	return ""
}

// parseFidel parses emails from fidel@hotmail.co.uk
func parseFidel(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		subject = ""
	}
	subjectLower := strings.ToLower(subject)

	// Get first paragraphs before "Received: from"
	parts := strings.Split(body, "Received: from")
	if len(parts) == 0 {
		return nil, common.NewParserError("no content before Received")
	}

	lines := strings.Split(parts[0], "\n")
	var firstParagraphs []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.Contains(trimmed, "eceived: from") {
			firstParagraphs = append(firstParagraphs, line)
		}
	}

	var eventsList []*events.Event
	var eventDate *time.Time
	if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
		eventDate = email.ParseDate(dates[0])
	}

	nEvents := 0
	for _, line := range firstParagraphs {
		event := events.NewEvent("fidel")

		url := getURL(line)
		if url != "" {
			event.URL = url
		}

		// Try to parse line as IP
		if validIP := common.IsIP(line); validIP != "" {
			event.IP = validIP
		}

		if event.IP != "" || url != "" {
			event.EventDate = eventDate
			if strings.Contains(subjectLower, "phishing") {
				event.EventTypes = []events.EventType{events.NewPhishingWithOfficialURL(url)}
			} else {
				if nEvents == 0 {
					event.EventTypes = []events.EventType{events.NewSpam()}
				} else {
					event.EventTypes = []events.EventType{events.NewSpamvertised()}
				}
				nEvents++
			}
			eventsList = append(eventsList, event)
		}
	}

	return eventsList, nil
}

// parseChrisRaper parses emails from chrisraper@hotmail.com
func parseChrisRaper(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		subject = ""
	}
	subjectLower := strings.ToLower(subject)

	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	bodyLower := strings.ToLower(body)

	event := events.NewEvent("hotmail")

	// Try to get IP from subject
	if validIP := common.IsIP(subjectLower); validIP != "" {
		event.IP = validIP
	} else {
		// Try to find in body
		ip := common.FindStringWithoutMarkers(bodyLower, "operating from ", " ")
		if validIP := common.IsIP(ip); validIP != "" {
			event.IP = validIP
		}
	}

	// Only create events with IP
	if event.IP == "" {
		return nil, nil
	}

	// Determine event type
	if strings.Contains(subjectLower, "phishing") || strings.Contains(bodyLower, "phishing") {
		event.EventTypes = []events.EventType{events.NewPhishing()}
	} else if strings.Contains(subjectLower, "spam") || strings.Contains(bodyLower, "spam") {
		event.EventTypes = []events.EventType{events.NewSpam()}
	} else {
		return nil, common.NewNewTypeError(subjectLower)
	}

	if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
		event.EventDate = email.ParseDate(dates[0])
	}

	return []*events.Event{event}, nil
}

// parseSoniaBonnefoy parses emails from soniabonnefoy@hotmail.fr
func parseSoniaBonnefoy(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	if !strings.Contains(subjectLower, "spam") {
		return nil, common.NewNewTypeError(subjectLower)
	}

	// Find IPs in received headers
	receivedRe := regexp.MustCompile(`(?i)received: from (?P<url>\S+) \((?P<ip>\S+)\)`)
	matches := receivedRe.FindAllStringSubmatch(body, -1)

	if len(matches) == 0 {
		return nil, common.NewParserError("no received headers found")
	}

	// Get the last IP
	lastMatch := matches[len(matches)-1]
	if len(lastMatch) < 3 {
		return nil, common.NewParserError("malformed received header")
	}

	event := events.NewEvent("hotmail")
	if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
		event.EventDate = email.ParseDate(dates[0])
	}
	event.EventTypes = []events.EventType{events.NewSpam()}
	event.IP = lastMatch[2]

	return []*events.Event{event}, nil
}

// parseKlowson parses emails from klowson@hotmail.com
func parseKlowson(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	if !strings.Contains(subjectLower, "spam report") {
		return nil, common.NewParserError("not a spam report")
	}

	var eventsList []*events.Event
	event := events.NewEvent("hotmail")
	event.EventTypes = []events.EventType{events.NewSpam()}
	if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
		event.EventDate = email.ParseDate(dates[0])
	}

	// Try to get IP from subject
	if validIP := common.IsIP(subjectLower); validIP != "" {
		event.IP = validIP
	} else {
		// Try to find in body
		ipRe := regexp.MustCompile(`(?i)(IP address)[^.0-9]*(\[?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\]?)`)
		if match := ipRe.FindStringSubmatch(body); match != nil && len(match) >= 3 {
			event.IP = match[2]
		}
	}

	bodyLower := strings.ToLower(body)
	// Check if we should yield the IP-only event
	hasURLMarker := strings.Contains(bodyLower, "following stackpath link:") ||
		strings.Contains(bodyLower, "uses your image links:") ||
		strings.Contains(bodyLower, "web site:") ||
		strings.Contains(bodyLower, "following site:")

	if !hasURLMarker && event.IP != "" {
		eventsList = append(eventsList, event)
	}

	// Look for URL
	urlRe := regexp.MustCompile(`(?i)((web site:|following site:|uses your image links:|following stackpath link:))\s*[^h.]*(?P<url>([^\s]+))`)
	if match := urlRe.FindStringSubmatch(body); match != nil && len(match) >= 4 {
		urlEvent := events.NewEvent("hotmail")
		urlEvent.EventTypes = []events.EventType{events.NewSpam()}
		if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
			urlEvent.EventDate = email.ParseDate(dates[0])
		}
		urlEvent.IP = event.IP
		urlEvent.URL = match[3]
		eventsList = append(eventsList, urlEvent)
	}

	return eventsList, nil
}

// parseGgrotyohann parses emails from ggrotyohann@hotmail.com
func parseGgrotyohann(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	ipRe := regexp.MustCompile(`(?i)(sender ip is)[^.0-9]*(\[?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\]?)`)
	if match := ipRe.FindStringSubmatch(body); match != nil && len(match) >= 3 {
		event := events.NewEvent("hotmail")
		event.EventTypes = []events.EventType{events.NewSpam()}
		if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
			event.EventDate = email.ParseDate(dates[0])
		}
		event.IP = match[2]
		return []*events.Event{event}, nil
	}

	return nil, common.NewParserError("no IP found")
}

// parseBoxrain parses emails from boxrain@hotmail.com
func parseBoxrain(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("no body found")
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		subject = ""
	}

	event := events.NewEvent("hotmail")
	if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
		event.EventDate = email.ParseDate(dates[0])
	}

	if strings.Contains(strings.ToLower(subject), "spam") {
		// Check for phishing URL
		phishRe := regexp.MustCompile(`(?i)(phishing in\s*(?P<url>http\S+))`)
		if match := phishRe.FindStringSubmatch(body); match != nil && len(match) >= 3 {
			event.EventTypes = []events.EventType{events.NewPhishingWithOfficialURL(match[2])}
			event.URL = match[2]
		} else {
			// Check for malware URL
			malwareRe := regexp.MustCompile(`(?i)(malware in\s*(?P<url>http\S+))`)
			if match := malwareRe.FindStringSubmatch(body); match != nil && len(match) >= 3 {
				event.EventTypes = []events.EventType{events.NewMalware("")}
				event.URL = match[2]
			} else {
				event.EventTypes = []events.EventType{events.NewSpam()}
			}
		}

		// Look for IP
		ipRe := regexp.MustCompile(`(?i)((spam and fraud from )?IP\s*(?P<ip>\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}))`)
		if match := ipRe.FindStringSubmatch(body); match != nil && len(match) >= 4 {
			if validIP := common.IsIP(match[3]); validIP != "" {
				event.IP = validIP
				return []*events.Event{event}, nil
			}
		}
	}

	return nil, nil
}

// parseBgstern19 parses emails from bgstern19@hotmail.com
func parseBgstern19(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("no body found")
	}

	parts := strings.Split(strings.ToLower(body), "received: from")
	if len(parts) < 2 {
		return nil, common.NewParserError("no received headers found")
	}

	// Get the last received header
	header := parts[len(parts)-1]
	ip := common.ExtractOneIP(header)

	// If private IP and we have more headers, use the second-to-last
	if strings.HasPrefix(ip, "127") && len(parts) > 2 {
		header = parts[len(parts)-2]
		ip = common.ExtractOneIP(header)
	}

	if ip == "" {
		return nil, common.NewParserError("couldn't find an IP")
	}

	event := events.NewEvent("hotmail")
	event.IP = ip
	if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
		event.EventDate = email.ParseDate(dates[0])
	}
	event.EventTypes = []events.EventType{events.NewSpam()}

	return []*events.Event{event}, nil
}

// parseTatayee parses emails from tatayee@hotmail.com
func parseTatayee(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("no body found")
	}
	bodyLower := strings.ToLower(body)

	event := events.NewEvent("hotmail")
	event.EventTypes = []events.EventType{events.NewSpam()}

	receivedBlock := common.FindString(bodyLower, "received: from", ";")
	if receivedBlock != "" {
		dateStr := common.FindStringWithoutMarkers(bodyLower, receivedBlock, "")
		event.EventDate = email.ParseDate(dateStr)
	}

	event.IP = common.FindStringWithoutMarkers(bodyLower, "subscriber [", "]")

	return []*events.Event{event}, nil
}

// parseColej2000 parses emails from colej2000@hotmail.com
func parseColej2000(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("no body found")
	}
	bodyLower := strings.ToLower(body)

	event := events.NewEvent("hotmail")
	event.EventTypes = []events.EventType{events.NewSpam()}

	receivedBlock := common.FindString(bodyLower, "received: from", ";")
	if receivedBlock != "" {
		dateStr := common.FindStringWithoutMarkers(bodyLower, receivedBlock, "")
		parsedDate := email.ParseDate(dateStr)
		if parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	// If we didn't get a date from received, use header date
	if event.EventDate == nil {
		if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
			event.EventDate = email.ParseDate(dates[0])
		}
	}

	if strings.Contains(bodyLower, "x-originating-ip:") {
		event.IP = common.FindStringWithoutMarkers(bodyLower, "x-originating-ip:", "")
	} else {
		event.IP = common.FindStringWithoutMarkers(bodyLower, "authentication-results: spf", "")
	}

	return []*events.Event{event}, nil
}

// parseBlockg parses emails from blockg@hotmail.com
func parseBlockg(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("no body found")
	}
	bodyLower := strings.ToLower(body)

	event := events.NewEvent("hotmail")
	event.EventTypes = []events.EventType{events.NewSpam()}
	if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
		event.EventDate = email.ParseDate(dates[0])
	}

	ip := common.FindStringWithoutMarkers(bodyLower, "sender ip:", "")
	if ip != "" {
		event.IP = ip
	} else {
		event.IP = common.FindStringWithoutMarkers(bodyLower, "spf=pass (sender ip is", ")")
	}

	return []*events.Event{event}, nil
}

// Helper functions

// setIP extracts and sets IP from headers or subject
func setIP(event *events.Event, serializedEmail *email.SerializedEmail) {
	var ip string

	// Check for cmm-sender-ip header
	if event.Headers != nil {
		if cmmEntry, ok := event.Headers["cmm-sender-ip"]; ok {
			if cmmStr, ok := cmmEntry.(string); ok {
				ip = common.IsIP(cmmStr)
			} else if cmmSlice, ok := cmmEntry.([]string); ok && len(cmmSlice) > 0 {
				ip = common.IsIP(cmmSlice[0])
			}
		}
	}

	// If not found, try to extract from subject
	if ip == "" {
		if subjects, ok := serializedEmail.Headers["subject"]; ok && len(subjects) > 0 {
			ip = common.ExtractOneIP(subjects[0])
			ip = common.IsIP(ip)
		}
	}

	if ip != "" {
		event.IP = ip
	}
}

// getDate extracts the event date from various sources
func getDate(serializedEmail *email.SerializedEmail) (*time.Time, error) {
	var possibleDateParts []string

	// Try parts[0].headers.date
	if len(serializedEmail.Parts) > 0 && serializedEmail.Parts[0].Headers != nil {
		if dates, ok := serializedEmail.Parts[0].Headers["date"]; ok && len(dates) > 0 {
			possibleDateParts = append(possibleDateParts, dates[0])
		}
	}

	// Try parts[0].headers.received (last one)
	if len(serializedEmail.Parts) > 0 && serializedEmail.Parts[0].Headers != nil {
		if received, ok := serializedEmail.Parts[0].Headers["received"]; ok && len(received) > 0 {
			possibleDateParts = append(possibleDateParts, received[len(received)-1])
		}
	}

	// Try main headers.date
	if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
		possibleDateParts = append(possibleDateParts, dates[0])
	}

	// Try parsing each candidate
	for _, part := range possibleDateParts {
		if parsedDate := email.ParseDate(part); parsedDate != nil {
			return parsedDate, nil
		}
	}

	return nil, common.NewParserError("no date found")
}

// addHeader adds a header to the event's headers map
func addHeader(event *events.Event, key, value string) {
	if event.Headers == nil {
		event.Headers = make(map[string]interface{})
	}

	key = strings.ToLower(key)

	// If key already exists, convert to slice or append to existing slice
	if existing, ok := event.Headers[key]; ok {
		switch v := existing.(type) {
		case []string:
			event.Headers[key] = append(v, value)
		case string:
			event.Headers[key] = []string{v, value}
		default:
			event.Headers[key] = []string{value}
		}
	} else {
		event.Headers[key] = value
	}
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
