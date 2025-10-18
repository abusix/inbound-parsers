package certat

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
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
	// First, try to find CSV attachment in parts
	if len(serializedEmail.Parts) > 0 {
		csvData, found := p.findCSVAttachment(serializedEmail.Parts)
		if found {
			return p.createEventsFromCSV(csvData, serializedEmail)
		}
	}

	// If no CSV found, parse from body
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, &common.ParserError{Message: "no event created"}
	}

	return p.createEvent(serializedEmail, body)
}

// findCSVAttachment recursively searches for CSV attachment in email parts
func (p *Parser) findCSVAttachment(parts []email.EmailPart) (string, bool) {
	for _, part := range parts {
		// Check if this part has content-disposition header with .csv
		if part.Headers != nil {
			if disposition, ok := part.Headers["content-disposition"]; ok {
				for _, disp := range disposition {
					if strings.Contains(strings.ToLower(disp), ".csv") {
						// Extract body
						switch body := part.Body.(type) {
						case string:
							return body, true
						case []byte:
							return string(body), true
						}
					}
				}
			}
		}

		// Note: The Python code also checks nested parts structure, but the EmailPart
		// type in Go doesn't support nested parts in the same way. The current
		// implementation handles the flat Parts array which should be sufficient.
	}
	return "", false
}

// createEvent creates a single event from the email body
func (p *Parser) createEvent(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	event := events.NewEvent("certat")

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Try to find event date in body
	bodyLower := strings.ToLower(body)
	if timeRegex := regexp.MustCompile(`entdeckt am:(.*)`); timeRegex.MatchString(bodyLower) {
		matches := timeRegex.FindStringSubmatch(bodyLower)
		if len(matches) > 1 {
			dateStr := strings.TrimSpace(matches[1])
			if parsedDate := email.ParseDate(dateStr); parsedDate != nil {
				event.EventDate = parsedDate
			}
		}
	}

	// Determine event type from problem field
	if problemRegex := regexp.MustCompile(`problem.*:(.*)`); problemRegex.MatchString(bodyLower) {
		matches := problemRegex.FindStringSubmatch(bodyLower)
		if len(matches) > 1 {
			problem := strings.ToLower(strings.TrimSpace(matches[1]))
			if strings.Contains(problem, "phishing") {
				event.EventTypes = []events.EventType{events.NewPhishing()}
			} else if strings.Contains(problem, "defacement") {
				event.EventTypes = []events.EventType{events.NewDefacement()}
			}
		}
	}

	// Extract IP address
	if ipRegex := regexp.MustCompile(`ip.*:(.*)`); ipRegex.MatchString(bodyLower) {
		matches := ipRegex.FindStringSubmatch(bodyLower)
		if len(matches) > 1 {
			event.IP = strings.TrimSpace(matches[1])
		}
	}

	// Extract URL
	if urlRegex := regexp.MustCompile(`url:(.*)`); urlRegex.MatchString(bodyLower) {
		matches := urlRegex.FindStringSubmatch(bodyLower)
		if len(matches) > 1 {
			urlStr := strings.TrimSpace(matches[1])
			event.URL = common.CleanURL(urlStr)
		}
	}

	return []*events.Event{event}, nil
}

// createEventsFromCSV parses events from CSV data
func (p *Parser) createEventsFromCSV(data string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Replace semicolons with commas
	data = strings.ReplaceAll(data, ";", ",")

	// Parse CSV
	reader := csv.NewReader(strings.NewReader(data))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSV: %w", err)
	}

	if len(records) == 0 {
		return nil, &common.ParserError{Message: "CSV data is empty"}
	}

	// First row is headers
	headers := records[0]

	// Check for required fields
	hasTimeSource := false
	hasSourceIP := false
	for _, header := range headers {
		if header == "time.source" {
			hasTimeSource = true
		}
		if header == "source.ip" {
			hasSourceIP = true
		}
	}

	if !hasTimeSource || !hasSourceIP {
		return nil, &common.ParserError{
			Message: fmt.Sprintf("Report does not contain ip or date. Field names are: %v", headers),
		}
	}

	// Get email body for context
	body, _ := common.GetBody(serializedEmail, false)
	bodyLower := strings.ToLower(body)

	// Parse each row into an event
	var eventsList []*events.Event
	for i := 1; i < len(records); i++ {
		row := records[i]

		// Create a map from headers to values
		rowMap := make(map[string]string)
		for j, header := range headers {
			if j < len(row) {
				rowMap[header] = row[j]
			}
		}

		event := events.NewEvent("certat")

		// Set event date
		if timeSource, ok := rowMap["time.source"]; ok {
			event.EventDate = email.ParseDate(timeSource)
		}

		// Determine event type
		malwareName := rowMap["malware.name"]
		eventType := rowMap["classification.type"]
		classification := rowMap["classification.identifier"]
		extraStr := rowMap["extra"]

		// Parse extra JSON field
		var extra map[string]interface{}
		if extraStr != "" {
			_ = json.Unmarshal([]byte(extraStr), &extra)
		}

		// Set event type based on classification
		if malwareName != "" {
			event.EventTypes = []events.EventType{events.NewMalware(malwareName)}
		} else if strings.Contains(eventType, "compromised") && strings.Contains(bodyLower, "accounts") {
			event.EventTypes = []events.EventType{events.NewCompromisedAccount("")}
		} else if strings.Contains(eventType, "vulnerable") {
			if strings.HasPrefix(strings.ToLower(classification), "cve-") {
				event.EventTypes = []events.EventType{events.NewCVE(classification, "", "HIGH")}
			} else {
				event.EventTypes = []events.EventType{events.NewOpen("HIGH")}
			}
		} else if strings.Contains(eventType, "ddos-amplifier") {
			amplification := ""
			if extra != nil {
				if amp, ok := extra["amplification"]; ok {
					amplification = fmt.Sprintf("%v", amp)
				}
			}
			event.EventTypes = []events.EventType{events.NewDDosAmplification("", amplification)}
		} else if strings.HasPrefix(classification, "open-") || strings.HasPrefix(classification, "accessible-") {
			service := common.MapServiceStrings(classification)
			event.EventTypes = []events.EventType{events.NewOpen(service)}
		}

		// Set IP and port
		event.IP = rowMap["source.ip"]
		if portStr := rowMap["source.port"]; portStr != "" {
			if port, err := strconv.Atoi(portStr); err == nil {
				event.Port = port
			}
		}

		// Add transport protocol
		if protocol := rowMap["protocol.transport"]; protocol != "" {
			event.AddEventDetail(&events.TransportProtocol{Protocol: protocol})
		}

		// Set URL
		event.URL = rowMap["source.url"]

		// Add ASN
		if asn := rowMap["source.asn"]; asn != "" {
			event.AddEventDetail(&events.ASN{ASN: asn})
		}

		// Add target information
		target := &events.Target{
			IP:   rowMap["destination.ip"],
			Port: rowMap["destination.port"],
			URL:  rowMap["destination.url"],
		}
		event.AddEventDetail(target)

		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
