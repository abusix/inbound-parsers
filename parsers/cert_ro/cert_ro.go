package cert_ro

import (
	"regexp"
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
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)
	bodyLower := strings.ToLower(body)

	event := events.NewEvent("cert_ro")

	// Set event date from email header
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Route to appropriate handler based on subject/body patterns
	if strings.Contains(subjectLower, "malware") && !strings.Contains(bodyLower, "detalii") {
		return parseMalware(subjectLower, event)
	}

	if strings.Contains(subjectLower, "phishing domains") && !strings.Contains(subjectLower, "multiple") {
		return parsePhishingDomains(serializedEmail, body, event)
	}

	if strings.Contains(subjectLower, "phishing") ||
		strings.Contains(subjectLower, "fake page") ||
		strings.Contains(subjectLower, "malicious url") ||
		strings.Contains(subjectLower, "malicious domain") ||
		strings.Contains(subjectLower, "scam email") ||
		strings.Contains(subjectLower, "scam domain") ||
		strings.Contains(subjectLower, "fake news") ||
		(strings.Contains(subjectLower, "malware") && strings.Contains(bodyLower, "detalii")) {
		event.EventTypes = []events.EventType{events.NewPhishing()}
		return parseScam(serializedEmail, subject, bodyLower, event)
	}

	if strings.Contains(subjectLower, "fake shop") || strings.Contains(subjectLower, "fake trade") {
		event.EventTypes = []events.EventType{events.NewFraud()}
		return parseScam(serializedEmail, subject, bodyLower, event)
	}

	if strings.Contains(subjectLower, "securitate cibernetica") {
		if strings.Contains(body, "Portmapper Scan") {
			event.EventTypes = []events.EventType{events.NewPortScan()}
			return parseEntries(body, event)
		}
		if strings.Contains(body, "Phishing") {
			event.EventTypes = []events.EventType{events.NewPhishing()}
			return parseEntries(body, event)
		}
		if strings.Contains(body, "Malware") {
			event.EventTypes = []events.EventType{events.NewMalware("")}
			return parseEntries(body, event)
		}
	}

	if strings.Contains(subjectLower, "dnsc") {
		return parseDNSC(subjectLower, bodyLower, event)
	}

	return nil, &common.NewTypeError{Subject: subjectLower}
}

func parseMalware(subjectLower string, event *events.Event) ([]*events.Event, error) {
	malwareRe := regexp.MustCompile(`malware\s*(?P<name>.*)--`)
	matches := malwareRe.FindStringSubmatch(subjectLower)

	malware := ""
	if len(matches) > 1 {
		malware = strings.TrimSpace(matches[1])
	}

	event.EventTypes = []events.EventType{events.NewMalware(malware)}

	// Extract IP from subject (subjectLower is already the IP in this case)
	if ip := common.ExtractOneIP(subjectLower); ip != "" {
		event.IP = ip
		return []*events.Event{event}, nil
	}

	return nil, &common.ParserError{Message: "No IP found in malware subject"}
}

func parsePhishingDomains(serializedEmail *email.SerializedEmail, body string, eventTemplate *events.Event) ([]*events.Event, error) {
	eventTemplate.EventTypes = []events.EventType{events.NewPhishing()}

	entryRe := regexp.MustCompile(`(?i)\[\s*(?P<url>\S+)\s*]\s+--(?P<ip>.*)\s+.*\s+created on\s*(?P<date>\d{4}-\d{2}-\d{2})`)
	matches := entryRe.FindAllStringSubmatch(body, -1)

	var result []*events.Event
	for _, match := range matches {
		if len(match) > 3 {
			event := events.NewEvent("cert_ro")
			event.EventTypes = eventTemplate.EventTypes

			// Copy event date from template
			event.EventDate = eventTemplate.EventDate

			// Set specific date from entry
			eventDate := email.ParseDate(match[3])
			if eventDate != nil {
				event.EventDate = eventDate
			}

			// Extract IP
			if ip := common.ExtractOneIP(match[2]); ip != "" {
				event.IP = ip
			}

			// Set URL
			event.URL = common.CleanURL(match[1])

			result = append(result, event)
		}
	}

	return result, nil
}

func getURLs(body, tag string) []string {
	var result []string
	lines := common.GetBlockAfterWithStop(body, tag, "")

	for _, line := range lines {
		lineLower := strings.ToLower(line)
		if strings.Contains(lineLower, "hxxp") || strings.Contains(lineLower, "http") {
			result = append(result, line)
		}
	}

	return result
}

func parseScam(serializedEmail *email.SerializedEmail, subject, bodyLower string, event *events.Event) ([]*events.Event, error) {
	// reporter uses details and redirect url differently in different reports,
	// so ip and url need to be handled separately for some reports

	// Try different tags to find details
	var details []string

	// Try "details" tag with various approaches
	tag := "details"
	details = getURLs(bodyLower, tag)
	if len(details) == 0 {
		// Try with newline after tag
		bodyWithNewline := strings.Replace(bodyLower, tag, tag+"\n\n", 1)
		details = getURLs(bodyWithNewline, tag)
	}
	if len(details) == 0 {
		details = getURLs(bodyLower, "effective url:")
	}
	if len(details) == 0 {
		// Try Romanian "detalii" tag
		tag = "detalii"
		bodyWithNewline := strings.Replace(bodyLower, tag, tag+"\n\n", 1)
		details = getURLs(bodyWithNewline, tag)
		if len(details) == 0 {
			details = getURLs(bodyLower, tag)
		}
	}
	if len(details) == 0 {
		// Try regex pattern for "time passed"
		timePassedRe := regexp.MustCompile(`(?i)time passed[^.]*(?P<url>(http|hxxp):.*)`)
		if matches := timePassedRe.FindStringSubmatch(bodyLower); len(matches) > 1 {
			details = []string{matches[1]}
		}
	}
	if len(details) == 0 {
		tag = "evidence:"
		bodyWithNewline := strings.Replace(bodyLower, tag, tag+"\n\n", 1)
		details = getURLs(bodyWithNewline, tag)
	}

	// Find redirect URLs
	redirectURL := []string{}
	redirectLines := common.GetContinuousLinesUntilEmptyLine(bodyLower, "redirect url")
	for _, line := range redirectLines {
		lineLower := strings.ToLower(line)
		if strings.Contains(lineLower, "hxxp") || strings.Contains(lineLower, "http") {
			redirectURL = append(redirectURL, line)
		}
	}

	if len(redirectURL) == 0 {
		submittedLines := common.GetContinuousLinesUntilEmptyLine(bodyLower, "submitted url:")
		for _, line := range submittedLines {
			lineLower := strings.ToLower(line)
			if strings.Contains(lineLower, "hxxp") || strings.Contains(lineLower, "http") {
				redirectURL = append(redirectURL, line)
			}
		}
	}

	// Extract IPs from subject
	var ips []string
	for _, part := range strings.Split(subject, "/") {
		if ip := common.IsIP(part); ip != "" {
			ips = append(ips, ip)
		}
	}

	// Extract ASN from subject
	asnStr := common.FindString(subject, "as", "]")
	asnStr = strings.Trim(asnStr, "[]")
	asnStr = strings.ToUpper(asnStr)
	if asnStr != "" {
		event.AddEventDetail(&events.ASN{ASN: asnStr})
	}

	var result []*events.Event

	// Create events for detail URLs
	for _, detailURL := range details {
		detailsEvent := events.NewEvent("cert_ro")
		detailsEvent.EventTypes = event.EventTypes
		detailsEvent.EventDate = event.EventDate
		detailsEvent.EventDetails = append([]events.EventDetail{}, event.EventDetails...)
		detailsEvent.URL = common.CleanURL(detailURL)
		result = append(result, detailsEvent)
	}

	// Set redirect URL if found
	if len(redirectURL) > 0 {
		event.URL = common.CleanURL(redirectURL[0]) // have only ever seen one
	}

	// Create events for IPs
	for _, ip := range ips {
		ipEvent := events.NewEvent("cert_ro")
		ipEvent.EventTypes = event.EventTypes
		ipEvent.EventDate = event.EventDate
		ipEvent.EventDetails = append([]events.EventDetail{}, event.EventDetails...)
		ipEvent.IP = ip
		if event.URL != "" {
			ipEvent.URL = event.URL
		}
		result = append(result, ipEvent)
	}

	// If we have a URL in the base event, add it
	if event.URL != "" && len(ips) == 0 {
		result = append(result, event)
	}

	return result, nil
}

func parseEntries(body string, eventTemplate *events.Event) ([]*events.Event, error) {
	parts := strings.Split(body, "src_domain_tld,additional_data")
	if len(parts) < 2 {
		return nil, &common.ParserError{Message: "Could not find entry block"}
	}

	entryBlock := strings.ReplaceAll(parts[len(parts)-1], "\"", "")

	entryRe := regexp.MustCompile(`(?P<date>\d{4}-\d{2}-\d{2}(T| )\d{2}:\d{2}:\d{2}(\S{6}|)),(?P<ip>\S+)`)
	matches := entryRe.FindAllStringSubmatch(entryBlock, -1)

	var result []*events.Event
	for _, match := range matches {
		if len(match) > 4 {
			event := events.NewEvent("cert_ro")
			event.EventTypes = eventTemplate.EventTypes

			// Parse date
			dateStr := match[1]
			eventDate := email.ParseDate(dateStr)
			if eventDate != nil {
				event.EventDate = eventDate
			}

			// Extract IP
			if ip := common.ExtractOneIP(match[4]); ip != "" {
				event.IP = ip
			}

			result = append(result, event)
		}
	}

	return result, nil
}

func parseDNSC(subjectLower, bodyLower string, event *events.Event) ([]*events.Event, error) {
	subject := strings.ReplaceAll(subjectLower, "  ", " ")

	// Determine event type
	if strings.Contains(subject, "ddos") {
		event.EventTypes = []events.EventType{events.NewDDoS()}
	} else if strings.Contains(subject, "web exploitation") {
		event.EventTypes = []events.EventType{events.NewWebHack()}
	} else if regexp.MustCompile(`(?i)(cyber.*security)`).MatchString(subject) || strings.Contains(subject, "incident de securitate") {
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
	}

	// Try to extract IP from subject
	if ip := common.ExtractOneIP(subject); ip != "" {
		event.IP = ip
		return []*events.Event{event}, nil
	}

	// Try to extract IP from body
	ipBlock := common.GetBlockAfterWithStop(bodyLower, "DETAILS ------------", "")
	for _, line := range ipBlock {
		if ip := common.ExtractOneIP(line); ip != "" {
			event.IP = ip
			return []*events.Event{event}, nil
		}
	}

	return nil, &common.ParserError{Message: "Didn't find any IP"}
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
