package cert_ee

import (
	"encoding/csv"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
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

	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	// Try CSV parsing first
	if len(serializedEmail.Parts) > 1 {
		if csvEvents, err := p.parseCSV(serializedEmail); err == nil {
			return csvEvents, nil
		}
	}

	// Parse based on subject/body content
	if strings.Contains(subjectLower, "phishing") || strings.Contains(strings.ToLower(body), "phishing") {
		return p.parseFraud(serializedEmail, body, events.NewPhishing())
	} else if strings.Contains(subjectLower, "malicious") || strings.Contains(subjectLower, "fraudulent") || strings.Contains(subjectLower, "scam website") {
		return p.parseFraud(serializedEmail, body, events.NewFraud())
	} else if strings.Contains(subjectLower, "konfiguratsiooniviga") && strings.Contains(strings.ToLower(body), "on lubatud") {
		return p.parseSimpleOpen(serializedEmail, body)
	} else if strings.Contains(subjectLower, "automated vunerability / abuse report") {
		return p.parseSimpleOpen(serializedEmail, body)
	}

	return nil, common.NewNewTypeError(subjectLower)
}

func (p *Parser) parseFraud(serializedEmail *email.SerializedEmail, body string, eventType events.EventType) ([]*events.Event, error) {
	var evts []*events.Event
	ips := make(map[string]bool)

	bodyLower := strings.ToLower(body)

	// Extract IPs around "ip address" marker
	ipPattern := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	blockLines := common.GetBlockAround(bodyLower, "ip address")
	for _, line := range blockLines {
		matches := ipPattern.FindAllString(line, -1)
		for _, ip := range matches {
			ips[ip] = true
		}
	}

	// Extract URL
	url := common.FindStringWithoutMarkers(bodyLower, "hxxp", "")
	if url != "" {
		url = "http" + url
	} else {
		return nil, common.NewParserError("url not found adapt parser")
	}

	// Extract date
	var eventDate *time.Time
	if strings.Contains(bodyLower, "first detection") {
		dateStr := common.FindStringWithoutMarkers(bodyLower, "first detection", "")
		if dateStr != "" {
			parts := strings.Split(dateStr, ":")
			if len(parts) > 1 {
				dateStr = strings.TrimSpace(parts[1])
				// Parse format like "30-Oct-2025 14:30:00 UTC"
				// Split into components
				dateRe := regexp.MustCompile(`(\d+)-(\w+)-(\d+)\s+(\d+:\d+:\d+)\s+(\w+)`)
				if matches := dateRe.FindStringSubmatch(dateStr); len(matches) > 5 {
					day, month, year, timeStr, tz := matches[1], matches[2], matches[3], matches[4], matches[5]
					parsedDate := fmt.Sprintf("%s-%s-%s %s:00 %s", year, month, day, timeStr, strings.ToUpper(tz))
					// Parse the date
					t, _ := time.Parse("2006-Jan-02 15:04:05 MST", parsedDate)
					eventDate = &t
				}
			}
		}
	}

	if eventDate == nil {
		// Use email date header
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			t := email.ParseDate(dateHeaders[0])
			eventDate = t
		}
	}

	// Extract screenshot links
	var screenshots []events.UrlStore
	screenshotLines := common.GetBlockAround(bodyLower, "please see attached screenshot")
	for _, line := range screenshotLines {
		if strings.Contains(line, "http") {
			parts := strings.Split(line, "http")
			if len(parts) > 1 {
				screenshots = append(screenshots, events.UrlStore{
					Description: "screenshot",
					URL:         "http" + parts[1],
				})
			}
		}
	}

	// Set phishing URL if applicable
	if phishingType, ok := eventType.(*events.Phishing); ok {
		phishingType.PhishingTarget = url
	}

	// Create events for each IP
	for ip := range ips {
		event := events.NewEvent("cert_ee")
		event.IP = ip
		event.URL = url
		event.EventTypes = []events.EventType{eventType}
		event.EventDate = eventDate

		if len(screenshots) > 0 {
			evidence := &events.Evidence{URLs: screenshots}
			event.AddEventDetail(evidence)
		}

		evts = append(evts, event)
	}

	// If no IPs found but we have a URL, create an event with just the URL
	if len(evts) == 0 && url != "" {
		event := events.NewEvent("cert_ee")
		event.URL = url
		event.EventTypes = []events.EventType{eventType}
		event.EventDate = eventDate
		evts = append(evts, event)
	}

	return evts, nil
}

func (p *Parser) parseCSV(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	csvFile, err := common.ExtractCSVFromEmail(serializedEmail)
	if err != nil {
		return nil, err
	}

	csvFileLower := strings.ToLower(csvFile)
	reader := csv.NewReader(strings.NewReader(csvFileLower))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, common.NewParserError("empty CSV")
	}

	headers := records[0]
	var evts []*events.Event
	ipCombinations := make(map[string]bool)

	for i := 1; i < len(records); i++ {
		entry := make(map[string]string)
		for j, value := range records[i] {
			if j < len(headers) {
				entry[headers[j]] = value
			}
		}

		ip := common.FindValueFromKeylist([]string{"source_ip", "_scanner_ip"}, entry)
		port := common.FindValueFromKeylist([]string{"source_port", "_scanner_port"}, entry)
		date := common.FindValueFromKeylist([]string{"time_observation", "time"}, entry)
		date = strings.ReplaceAll(date, "_", " ")
		protocol := common.FindValueFromKeylist([]string{"protocol", "_protocol"}, entry)
		identifier := common.FindValueFromKeylist([]string{"classification_identifier", "_category"}, entry)
		classTaxonomy := p.getCleanEntry(common.FindValueFromKeylist([]string{"classification_taxonomy"}, entry))
		classType := p.getCleanEntry(common.FindValueFromKeylist([]string{"classification_type"}, entry))
		asName := common.FindValueFromKeylist([]string{"source_as_name"}, entry)
		asn := common.FindValueFromKeylist([]string{"source_asn"}, entry)
		targetPort := common.FindValueFromKeylist([]string{"_victim_port"}, entry)

		// Determine event type
		var eventType events.EventType
		if identifier != "" && strings.Contains(identifier, "scan") {
			eventType = events.NewPortScan()
		} else if identifier != "" && strings.Contains(identifier, "open") {
			eventType = events.NewOpen(common.MapServiceStrings(identifier))
		} else if identifier != "" && strings.Contains(identifier, "blacklisted") {
			eventType = events.NewBlacklist("")
		} else if identifier != "" && strings.Contains(identifier, "ddos") {
			eventType = events.NewDDoS()
		} else if strings.Contains(classTaxonomy, "maliciouscode") && strings.Contains(classType, "infectedsystem") {
			eventType = events.NewCompromisedServer()
		} else if strings.Contains(identifier, "accessible-http") {
			eventType = events.NewCompromisedWebsite("")
		} else {
			return nil, common.NewNewTypeError(identifier)
		}

		// Deduplicate by IP:port
		combination := fmt.Sprintf("%s:%s", ip, port)
		if !ipCombinations[combination] {
			ipCombinations[combination] = true

			event := events.NewEvent("cert_ee")
			event.EventTypes = []events.EventType{eventType}
			event.IP = ip

			if port != "" {
				if p, err := common.ParseInt(port); err == nil {
					event.Port = p
				}
			}

			// Parse event date
			if date != "" {
				if t, err := time.Parse("2006-01-02 15:04:05", date); err == nil {
					event.EventDate = &t
				}
			}

			// Add ASN
			if asn != "" || asName != "" {
				event.AddEventDetail(&events.ASN{
					ASN:    asn,
					ASName: asName,
				})
			}

			// Add target port
			if targetPort != "" {
				event.AddEventDetail(&events.Target{Port: targetPort})
			}

			// Add protocol
			if protocol != "" {
				event.AddEventDetail(&events.TransportProtocol{Protocol: protocol})
			}

			// Add location
			country := entry["source_geolocation_cc"]
			city := entry["source_geolocation_city"]
			if country != "" || city != "" {
				event.AddEventDetail(&events.Location{
					Country: country,
					City:    city,
				})
			}

			evts = append(evts, event)
		}
	}

	return evts, nil
}

func (p *Parser) parseSimpleOpen(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	event := events.NewEvent("cert_ee")

	bodyLower := strings.ToLower(body)
	if strings.Contains(bodyLower, "directory listing") {
		event.EventTypes = []events.EventType{events.NewOpen(common.MapServiceStrings("directory listing"))}
	} else {
		return nil, common.NewNewTypeError("uncategorized open type")
	}

	url := common.FindStringWithoutMarkers(bodyLower, "on lubatud ", " ")
	event.URL = url

	// Use email date
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		t := email.ParseDate(dateHeaders[0])
		event.EventDate = t
	}

	return []*events.Event{event}, nil
}

func (p *Parser) getCleanEntry(entry string) string {
	entry = strings.ReplaceAll(entry, "-", "")
	entry = strings.ReplaceAll(entry, "_", "")
	entry = strings.ReplaceAll(entry, " ", "")
	return strings.TrimSpace(entry)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
