package cert_pl

import (
	"encoding/csv"
	"fmt"
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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)

	// Extract report type from subject
	var reportType string
	reportTypeRe := regexp.MustCompile(`.*\[(.*)\]`)
	if matches := reportTypeRe.FindStringSubmatch(subject); len(matches) > 1 {
		reportType = matches[1]
	}

	var evts []*events.Event

	// Route to appropriate parser based on subject/body content
	if reportType == "malicious code" {
		evts = p.parseMalware(subject, body, serializedEmail)
	} else if (reportType == "fraud" && strings.Contains(subject, "phishing")) || reportType == "phishing" {
		evts = p.parsePhishing(subject, body, serializedEmail)
	} else if strings.Contains(subject, "malware") || strings.Contains(subject, "szkodliwym") {
		evts, err = p.parseMalwareListFormat(serializedEmail, body)
		if err != nil {
			return nil, err
		}
	} else if strings.Contains(bodyLower, " ddos ") {
		evts, err = p.parseDDoS(body, serializedEmail)
		if err != nil {
			return nil, err
		}
	} else if strings.Contains(subjectLower, "dostępnej usłudze  mogącej stanowić zagrożenie:") {
		evts = p.parseOpen(subjectLower, bodyLower, serializedEmail)
	} else {
		return nil, common.NewNewTypeError(fmt.Sprintf("Unknown report type: %s or subject: %s", reportType, subject))
	}

	// Add common event details to all events
	for _, evt := range evts {
		evt.AddEventDetail(&events.Organisation{
			Name:         "reporter",
			Organisation: "Computer Security Incident Response Team CERT Polska",
		})

		// Add external ID from x-rt-ticket header if present
		if rtTicket, ok := serializedEmail.Headers["x-rt-ticket"]; ok && len(rtTicket) > 0 {
			evt.AddEventDetail(&events.ExternalID{
				ID: rtTicket[0],
			})
		}
	}

	return evts, nil
}

func (p *Parser) parseMalware(subject, body string, serializedEmail *email.SerializedEmail) []*events.Event {
	evt := events.NewEvent("cert_pl")

	// Extract malware name from subject: "... ] targeting <malware> hosted"
	malwareRe := regexp.MustCompile(`.*]\s+(?:targeting\s+)?(.*)\s+hosted`)
	var malwareName string
	if matches := malwareRe.FindStringSubmatch(subject); len(matches) > 1 {
		malwareName = matches[1]
	}

	evt.EventTypes = []events.EventType{events.NewMalware(malwareName)}
	evt.IP = common.FindStringWithoutMarkers(body, "hosts malicious content on ", ",")
	evt.URL = common.GetNonEmptyLineAfter(body, "URLs:")

	// Set event date from email date header
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		evt.EventDate = email.ParseDate(dateHeaders[0])
	}

	return []*events.Event{evt}
}

func (p *Parser) parseMalwareListFormat(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	var text string

	// Check for HTML part
	for _, part := range serializedEmail.Parts {
		if part.Headers != nil {
			if contentType, ok := part.Headers["content-type"]; ok && len(contentType) > 0 {
				if strings.Contains(strings.ToLower(contentType[0]), "text/html") {
					// Extract text from HTML part
					if htmlBody, ok := part.Body.(string); ok {
						text = htmlBody
					} else if htmlBytes, ok := part.Body.([]byte); ok {
						text = string(htmlBytes)
					}
					break
				}
			}
		}
	}

	// If no HTML part found, use body
	if text == "" {
		text = body
	}

	// Clean the CSV format
	cleaned := regexp.MustCompile(`,\s+"`).ReplaceAllString(text, `,"`)

	// Extract CSV block around "asn"
	block := common.GetBlockAround(cleaned, `"asn",`)

	// Remove lines until we find the header with "asn"
	var csvLines []string
	foundHeader := false
	for _, line := range block {
		if !foundHeader && strings.Contains(line, "asn") {
			foundHeader = true
		}
		if foundHeader {
			csvLines = append(csvLines, line)
		}
	}

	if len(csvLines) == 0 {
		return nil, fmt.Errorf("no CSV data found with asn header")
	}

	// Parse CSV
	reader := csv.NewReader(strings.NewReader(strings.Join(csvLines, "\n")))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSV: %w", err)
	}

	if len(records) < 2 {
		return nil, fmt.Errorf("insufficient CSV data")
	}

	// First row is headers
	headers := records[0]
	var evts []*events.Event

	for i := 1; i < len(records); i++ {
		row := records[i]
		entry := make(map[string]string)
		for j, value := range row {
			if j < len(headers) {
				entry[headers[j]] = value
			}
		}

		evt := events.NewEvent("cert_pl")
		evt.EventTypes = []events.EventType{events.NewMalware(entry["malware"])}
		evt.IP = entry["ip"]

		// Add target detail
		evt.AddEventDetail(&events.Target{
			IP:   entry["dst_ip"],
			Port: entry["dst_port"],
			URL:  entry["dst_host"],
		})

		evt.EventDate = email.ParseDate(entry["timestamp"])
		evts = append(evts, evt)
	}

	return evts, nil
}

func (p *Parser) parsePhishing(subject, body string, serializedEmail *email.SerializedEmail) []*events.Event {
	// Extract IP from subject: "... ] hosted on <IP>"
	var ip string
	ipRe := regexp.MustCompile(`.*]\s+hosted\s+on\s+((?:[0-9]{1,3}\.){3}[0-9]{1,3})`)
	if matches := ipRe.FindStringSubmatch(subject); len(matches) > 1 {
		ip = matches[1]
	}

	eventTemplate := events.NewEvent("cert_pl")
	eventTemplate.IP = ip

	// Set event date from email date header
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventTemplate.EventDate = email.ParseDate(dateHeaders[0])
	}

	var evts []*events.Event

	// Check for multiple URLs
	if strings.Contains(body, "following URLs:") {
		urls := common.GetContinuousLinesUntilEmptyLine(body, "following URLs:")
		for _, url := range urls {
			evt := events.NewEvent("cert_pl")
			evt.IP = eventTemplate.IP
			evt.EventDate = eventTemplate.EventDate
			evt.URL = strings.TrimSpace(url)

			// Create phishing event
			phishing := events.NewPhishing()
			evt.EventTypes = []events.EventType{phishing}

			evts = append(evts, evt)
		}
	} else {
		// Single phishing event without specific URL
		eventTemplate.EventTypes = []events.EventType{events.NewPhishing()}
		evts = append(evts, eventTemplate)
	}

	return evts
}

func (p *Parser) parseDDoS(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	var evts []*events.Event

	// Try to find CSV attachment
	csvAttachment, err := common.FindFirstAttachmentWithMimeType(serializedEmail, "text/csv")

	if err == nil && csvAttachment != "" {
		// Parse CSV attachment
		reader := csv.NewReader(strings.NewReader(csvAttachment))
		records, err := reader.ReadAll()
		if err != nil {
			return nil, fmt.Errorf("failed to parse CSV attachment: %w", err)
		}

		if len(records) < 2 {
			return nil, fmt.Errorf("insufficient CSV data in attachment")
		}

		// First row is headers
		headers := records[0]
		for i := 1; i < len(records); i++ {
			row := records[i]
			entry := make(map[string]string)
			for j, value := range row {
				if j < len(headers) {
					entry[headers[j]] = value
				}
			}

			evt := events.NewEvent("cert_pl")
			evt.EventTypes = []events.EventType{events.NewDDoS()}
			evt.IP = entry["IP Address"]

			// Set event date from email date header
			if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
				evt.EventDate = email.ParseDate(dateHeaders[0])
			}

			evts = append(evts, evt)
		}
	} else {
		// Parse from body text
		infoRe := regexp.MustCompile(`(?i)conducted\son(.*)between.*targeting\ssite(.*)\((.*)\)`)
		if matches := infoRe.FindStringSubmatch(body); len(matches) > 3 {
			evt := events.NewEvent("cert_pl")
			evt.EventTypes = []events.EventType{events.NewDDoS()}
			evt.IP = strings.TrimSpace(matches[3])

			// Add target detail
			targetURL := strings.TrimSpace(matches[2])
			evt.AddEventDetail(&events.Target{
				URL: targetURL,
			})

			// Parse event date from match
			dateStr := strings.TrimSpace(matches[1]) + " 00:00:00 UTC"
			evt.EventDate = email.ParseDate(dateStr)

			evts = append(evts, evt)
		} else {
			return nil, fmt.Errorf("unknown ddos format")
		}
	}

	return evts, nil
}

func (p *Parser) parseOpen(subjectLower, bodyLower string, serializedEmail *email.SerializedEmail) []*events.Event {
	evt := events.NewEvent("cert_pl")

	// Set event date from email date header
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		evt.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Extract service from subject (after last colon)
	parts := strings.Split(subjectLower, ":")
	service := ""
	if len(parts) > 0 {
		service = strings.TrimSpace(parts[len(parts)-1])
	}

	evt.EventTypes = []events.EventType{events.NewOpen(service)}
	evt.IP = strings.TrimSpace(bodyLower)

	return []*events.Event{evt}
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
