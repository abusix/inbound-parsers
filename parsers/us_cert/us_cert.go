package us_cert

import (
	"encoding/csv"
	"fmt"
	"net"
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

// Match returns true if the email is from US-CERT
func Match(fromAddr string) bool {
	if fromAddr != "" && strings.Contains(fromAddr, "@us-cert.gov") {
		return true
	}
	return false
}

// Parse parses US-CERT abuse reports
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Check for CSV attachment first (Shadowserver data)
	if csvPart, err := common.FindFirstAttachmentWithMimeType(serializedEmail, "csv"); err == nil {
		return parseShadowserverCSV(serializedEmail, csvPart)
	}

	// Parse email body
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get email body: %w", err)
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get email subject: %w", err)
	}

	// Create event template
	eventTemplate := events.NewEvent("us_cert")

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
			eventTemplate.EventDate = parsedDate
		}
	}

	// Extract external ID from subject (between "number " and " ")
	externalID := common.FindStringWithoutMarkers(subject, "number ", " ")
	if externalID != "" {
		eventTemplate.AddEventDetail(&events.ExternalID{ID: externalID})
	}

	// Determine parsing strategy based on body content
	bodyLower := strings.ToLower(body)

	if strings.Contains(bodyLower, "botnet") {
		return parseBot(body, eventTemplate)
	} else if strings.Contains(bodyLower, "redirect vulnerability") ||
		strings.Contains(bodyLower, "phishing") {
		return parsePhishing(body, eventTemplate)
	} else if strings.Contains(bodyLower, "malicious activity") {
		return parseMaliciousActivity(body, eventTemplate)
	}

	return nil, fmt.Errorf("CSV part not found and no recognized pattern in body")
}

// parsePhishing parses phishing-related reports
func parsePhishing(body string, eventTemplate *events.Event) ([]*events.Event, error) {
	eventTemplate.EventTypes = []events.EventType{events.NewPhishing()}
	var results []*events.Event

	// Pattern 1: "URL: <url>"
	if urlMatch := regexp.MustCompile(`URL:\s+(?P<url>\S+)`).FindStringSubmatch(body); urlMatch != nil {
		eventTemplate.URL = urlMatch[1]

		// Check for proof URL
		if proofMatch := regexp.MustCompile(`description: open this link (?P<url>http\S+)`).FindStringSubmatch(body); proofMatch != nil {
			evidence := &events.Evidence{}
			evidence.AddEvidence(events.UrlStore{URL: proofMatch[1]})
			eventTemplate.AddEventDetail(evidence)
		}
		results = append(results, eventTemplate)
		return results, nil
	}

	// Pattern 2: "phishing url: <url> ip: <ip>"
	if urlMatch := regexp.MustCompile(`(?i)phishing url:\s+(?P<url>\S+)\s+ip:\s+(?P<ip>\S+)`).FindStringSubmatch(body); urlMatch != nil {
		eventTemplate.URL = urlMatch[1]
		eventTemplate.IP = strings.ReplaceAll(urlMatch[2], "[.]", ".")
		results = append(results, eventTemplate)
		return results, nil
	}

	// Pattern 3: "ip: <ip> <url>"
	if urlMatch := regexp.MustCompile(`(?i)ip:\s+(?P<ip>\S+)\s+(?P<url>http\S+)`).FindStringSubmatch(body); urlMatch != nil {
		eventTemplate.IP = urlMatch[1]
		url := urlMatch[2]

		if strings.HasPrefix(url, "https://urldefense.com") {
			evidence := &events.Evidence{}
			evidence.AddEvidence(events.UrlStore{URL: url})
			eventTemplate.AddEventDetail(evidence)
		} else {
			eventTemplate.URL = url
		}
		results = append(results, eventTemplate)
		return results, nil
	}

	// Pattern 4: "phishing ip: <ip> phishing url: <url>"
	if urlMatch := regexp.MustCompile(`(?i)phishing ip:\s+(?P<ip>\S+)\s+phishing url:\s+(?P<url>\S+)`).FindStringSubmatch(body); urlMatch != nil {
		eventTemplate.IP = strings.ReplaceAll(urlMatch[1], "[.]", ".")
		eventTemplate.URL = urlMatch[2]
		results = append(results, eventTemplate)
		return results, nil
	}

	// Pattern 5: Default - extract IP and URLs separately
	ip := common.FindStringWithoutMarkers(body, "IP: ", "")
	ip = strings.ReplaceAll(ip, "[.]", ".")

	urlBlock := common.FindStringWithoutMarkers(body, "Phishing URL:", "IP:")
	for _, url := range strings.Split(urlBlock, "\n") {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}

		// Try to parse as URL
		event := copyEvent(eventTemplate)
		event.IP = ip
		event.URL = url
		results = append(results, event)
	}

	if len(results) > 0 {
		return results, nil
	}

	return nil, fmt.Errorf("no phishing data found")
}

// parseMaliciousActivity parses malicious activity reports
func parseMaliciousActivity(body string, eventTemplate *events.Event) ([]*events.Event, error) {
	eventTemplate.EventTypes = []events.EventType{events.NewMaliciousActivity()}
	var results []*events.Event

	// Pattern 1: Fraudulent web site
	if strings.Contains(body, "Fraudulent web site:") {
		eventTemplate.EventTypes = []events.EventType{events.NewFraud()}

		data := common.GetContinuousLinesUntilEmptyLine(body, "Fraudulent web site:")
		for _, line := range data {
			if ip := extractOneIP(line); isIP(ip) {
				eventTemplate.IP = ip
				break
			}
		}

		for _, url := range data {
			url = strings.TrimSpace(url)
			if url == "" {
				continue
			}

			event := copyEvent(eventTemplate)
			event.URL = url
			results = append(results, event)
		}

		if len(results) > 0 {
			return results, nil
		}
	}

	// Pattern 2: "listed below are reported malicious:"
	if strings.Contains(strings.ToLower(body), "listed below are reported malicious:") {
		if urlMatch := regexp.MustCompile(`(?i)listed below are reported malicious:\s+(?P<ip>\S+)\s+(?P<url>http\S+)`).FindStringSubmatch(body); urlMatch != nil {
			eventTemplate.IP = strings.ReplaceAll(urlMatch[1], "[.]", ".")
			eventTemplate.URL = urlMatch[2]
			results = append(results, eventTemplate)
			return results, nil
		}

		ip := common.GetNonEmptyLineAfter(body, "listed below are reported malicious:")
		ip = strings.ReplaceAll(ip, "[.]", ".")
		eventTemplate.IP = ip
		results = append(results, eventTemplate)
		return results, nil
	}

	// Pattern 3: "= <ip> ="
	if ipMatch := regexp.MustCompile(`=\s+(?P<ip>\S+)\s+=`).FindStringSubmatch(body); ipMatch != nil {
		eventTemplate.IP = ipMatch[1]
		results = append(results, eventTemplate)
		return results, nil
	}

	// Pattern 4: Default - extract IP and URLs separately
	ip := common.FindStringWithoutMarkers(body, "IP Address:", "")
	ip = strings.ReplaceAll(ip, " . ", ".")
	ip = strings.ReplaceAll(ip, "[.]", ".")

	urlBlock := common.FindStringWithoutMarkers(body, "Suspect URLs:", "IP Address:")
	for _, url := range strings.Split(urlBlock, "\n") {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}

		event := copyEvent(eventTemplate)
		event.IP = ip
		event.URL = url
		results = append(results, event)
	}

	if len(results) > 0 {
		return results, nil
	}

	return nil, fmt.Errorf("no malicious activity data found")
}

// parseBot parses botnet infection reports
func parseBot(body string, event *events.Event) ([]*events.Event, error) {
	botType := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Malware:", ""))
	event.EventTypes = []events.EventType{events.NewBot(botType)}

	event.IP = common.FindStringWithoutMarkers(body, "IP address:", "Port")

	portStr := common.FindStringWithoutMarkers(body, "Port:", "")
	if port, err := common.ParsePort(portStr); err == nil {
		event.Port = port
	}

	// Extract event date
	eventDateStr := common.FindStringWithoutMarkers(body, "Last seen:", "")
	if parsedDate := email.ParseDate(eventDateStr); parsedDate != nil {
		event.EventDate = parsedDate
	}

	// Extract proof URL as evidence
	proofURL := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Proof:", ""))
	if proofURL != "" {
		evidence := &events.Evidence{}
		evidence.AddEvidence(events.UrlStore{URL: proofURL})
		event.AddEventDetail(evidence)
	}

	return []*events.Event{event}, nil
}

// parseShadowserverCSV parses CSV attachments (Shadowserver format)
func parseShadowserverCSV(serializedEmail *email.SerializedEmail, csvContent string) ([]*events.Event, error) {
	reader := csv.NewReader(strings.NewReader(csvContent))
	reader.Comma = ','
	reader.LazyQuotes = true

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSV: %w", err)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("CSV is empty")
	}

	// Parse CSV using shadowserver bot type parsing
	// This is simplified - full implementation would need parseBotType helper
	var result []*events.Event
	headers := records[0]

	for i := 1; i < len(records); i++ {
		row := make(map[string]string)
		for j, value := range records[i] {
			if j < len(headers) {
				row[headers[j]] = value
			}
		}

		event := events.NewEvent("us_cert")
		event.EventTypes = []events.EventType{events.NewBot("")}

		// Extract basic fields
		if ip, ok := row["ip"]; ok {
			event.IP = ip
		}
		if port, ok := row["port"]; ok {
			if p, err := common.ParsePort(port); err == nil {
				event.Port = p
			}
		}

		result = append(result, event)
	}

	return result, nil
}

// copyEvent creates a deep copy of an event
func copyEvent(src *events.Event) *events.Event {
	dst := events.NewEvent(src.Parser)
	dst.IP = src.IP
	dst.URL = src.URL
	dst.Port = src.Port
	dst.Domain = src.Domain
	dst.EventDate = src.EventDate
	dst.EventTypes = make([]events.EventType, len(src.EventTypes))
	copy(dst.EventTypes, src.EventTypes)

	// Copy event details
	for _, detail := range src.EventDetails {
		dst.AddEventDetail(detail)
	}

	return dst
}

// extractOneIP extracts the first IP address from a string
func extractOneIP(text string) string {
	// IPv4 pattern
	ipPattern := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	if match := ipPattern.FindString(text); match != "" {
		return match
	}
	return ""
}

// isIP checks if a string is a valid IP address
func isIP(ip string) bool {
	if ip == "" {
		return false
	}
	return net.ParseIP(ip) != nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
