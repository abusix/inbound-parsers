package ncsc

import (
	"encoding/csv"
	"fmt"
	"strings"

	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// getValue retrieves the first non-empty value from a map using a list of keys
func getValue(row map[string]string, keys []string) string {
	for _, key := range keys {
		if val, ok := row[key]; ok && val != "" {
			return val
		}
	}
	return ""
}

// extractInfoCVE extracts CVE vulnerability information from CSV rows
func extractInfoCVE(eventTemplate *events.Event, rows []map[string]string, dateFallback string) (*events.Event, error) {
	for _, row := range rows {
		event := copyEvent(eventTemplate)

		// Extract IP and port
		event.IP = getValue(row, []string{"ip", "src_ip", ";ip"})
		portStr := getValue(row, []string{"port", "src_port", "local_port"})
		if portStr != "" {
			if port, err := common.ParsePort(portStr); err == nil {
				event.Port = port
			}
		}

		// Transport protocol
		protocol := getValue(row, []string{"protocol"})
		if protocol != "" {
			event.AddEventDetail(&events.TransportProtocol{Protocol: protocol})
		}

		// Location details
		city := getValue(row, []string{"city"})
		if city != "" {
			event.AddEventDetailSimple("city", city)
		}

		region := getValue(row, []string{"region", "src_region"})
		if region != "" {
			event.AddEventDetailSimple("region", region)
		}

		country := getValue(row, []string{"country", "src_geo"})
		if country != "" {
			event.AddEventDetailSimple("country", country)
		}

		deviceType := getValue(row, []string{"device_type"})
		if deviceType != "" {
			event.AddEventDetailSimple("device_type", deviceType)
		}

		// URL (may fail for invalid paths, ignore errors)
		url := getValue(row, []string{"url"})
		if url != "" {
			event.URL = url
		}

		// Target information
		dstIP := getValue(row, []string{"dst_ip"})
		dstPort := getValue(row, []string{"dst_port"})
		if dstIP != "" || dstPort != "" {
			event.AddEventDetail(&events.Target{
				IP:   dstIP,
				Port: dstPort,
			})
		}

		// Event date
		dateStr := getValue(row, []string{"lastseen", "time", "timestamp"})
		if dateStr != "" {
			if parsed := email.ParseDate(dateStr); parsed != nil {
				event.EventDate = parsed
			} else {
				// Fall back to email date
				if parsed := email.ParseDate(dateFallback); parsed != nil {
					event.EventDate = parsed
				}
			}
		} else {
			if parsed := email.ParseDate(dateFallback); parsed != nil {
				event.EventDate = parsed
			}
		}

		// CVE vulnerability
		vulnerability := getValue(row, []string{"tag", "tags"})
		event.EventTypes = []events.EventType{events.NewCVE(vulnerability, "", "")}

		return event, nil
	}

	return nil, fmt.Errorf("no rows to process")
}

// extractInfoMalware extracts malware information from CSV rows
func extractInfoMalware(eventTemplate *events.Event, rows []map[string]string, dateFallback string) (*events.Event, error) {
	for _, row := range rows {
		event := copyEvent(eventTemplate)

		// Extract IP and port
		event.IP = getValue(row, []string{"ip", "src_ip", ";ip"})
		portStr := getValue(row, []string{"port", "src_port", "local_port"})
		if portStr != "" {
			if port, err := common.ParsePort(portStr); err == nil {
				event.Port = port
			}
		}

		// Transport protocol
		protocol := getValue(row, []string{"protocol"})
		if protocol != "" {
			event.AddEventDetail(&events.TransportProtocol{Protocol: protocol})
		}

		// Location details
		city := getValue(row, []string{"city"})
		if city != "" {
			event.AddEventDetailSimple("city", city)
		}

		region := getValue(row, []string{"region", "src_region"})
		if region != "" {
			event.AddEventDetailSimple("region", region)
		}

		country := getValue(row, []string{"country", "src_geo"})
		if country != "" {
			event.AddEventDetailSimple("country", country)
		}

		deviceType := getValue(row, []string{"device_type"})
		if deviceType != "" {
			event.AddEventDetailSimple("device_type", deviceType)
		}

		// URL (may fail for invalid paths, ignore errors)
		url := getValue(row, []string{"url"})
		if url != "" {
			event.URL = url
		}

		// Target information
		dstIP := getValue(row, []string{"dst_ip"})
		dstPort := getValue(row, []string{"dst_port"})
		if dstIP != "" || dstPort != "" {
			event.AddEventDetail(&events.Target{
				IP:   dstIP,
				Port: dstPort,
			})
		}

		// Event date
		dateStr := getValue(row, []string{"lastseen", "time", "timestamp"})
		if dateStr != "" {
			if parsed := email.ParseDate(dateStr); parsed != nil {
				event.EventDate = parsed
			} else {
				// Fall back to email date
				if parsed := email.ParseDate(dateFallback); parsed != nil {
					event.EventDate = parsed
				}
			}
		} else {
			if parsed := email.ParseDate(dateFallback); parsed != nil {
				event.EventDate = parsed
			}
		}

		// Malware information
		malwareName := getValue(row, []string{"botname", "name"})
		event.EventTypes = []events.EventType{events.NewMalware(malwareName)}

		return event, nil
	}

	return nil, fmt.Errorf("no rows to process")
}

// copyEvent creates a deep copy of an event template
func copyEvent(template *events.Event) *events.Event {
	event := events.NewEvent(template.Parser)
	event.Headers = make(map[string]interface{})
	for k, v := range template.Headers {
		event.Headers[k] = v
	}
	return event
}

// parseCSV parses CSV data with optional TSV delimiter
func parseCSV(rawCSV string, delimiter rune) ([]map[string]string, error) {
	reader := csv.NewReader(strings.NewReader(rawCSV))
	reader.Comma = delimiter

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV: %w", err)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no CSV data found")
	}

	// First row is headers
	headers := records[0]
	var result []map[string]string

	for i := 1; i < len(records); i++ {
		row := make(map[string]string)
		for j, value := range records[i] {
			if j < len(headers) {
				row[headers[j]] = value
			}
		}
		result = append(result, row)
	}

	return result, nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	body = strings.ToLower(body)
	subject = strings.ToLower(subject)

	eventTemplate := events.NewEvent("ncsc")

	// Get date fallback from email headers
	dateFallback := ""
	if serializedEmail.Headers != nil {
		if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
			dateFallback = dateHeader[0]
		}
	}

	var rawCSV string
	var delimiter rune = ','

	// Try to find CSV or TSV attachment
	for _, ext := range []string{".csv", ".tsv"} {
		if content, err := common.FindFirstAttachmentWithMimeType(serializedEmail, ext); err == nil {
			rawCSV = content
			if ext == ".tsv" {
				delimiter = '\t'
			}
			break
		}
	}

	if rawCSV == "" {
		return nil, fmt.Errorf("didn't find attached CSV: %s", subject)
	}

	// Parse CSV/TSV data
	rows, err := parseCSV(rawCSV, delimiter)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSV: %w", err)
	}

	var result []*events.Event

	// Determine event type and extract information
	if strings.Contains(body, "vulnerabilities") || strings.Contains(body, "vulnerability") || strings.Contains(body, "vulnerable") {
		event, err := extractInfoCVE(eventTemplate, rows, dateFallback)
		if err != nil {
			return nil, err
		}
		result = append(result, event)

	} else if strings.Contains(body, "phishing") {
		// Phishing events
		for _, row := range rows {
			event := copyEvent(eventTemplate)
			event.URL = getValue(row, []string{"url", "phish_detail_url"})
			event.EventTypes = []events.EventType{events.NewPhishing()}

			// Event date
			dateStr := getValue(row, []string{"submission_time"})
			if dateStr != "" {
				if parsed := email.ParseDate(dateStr); parsed != nil {
					event.EventDate = parsed
				} else {
					// Fall back to email date
					if parsed := email.ParseDate(dateFallback); parsed != nil {
						event.EventDate = parsed
					}
				}
			} else {
				if parsed := email.ParseDate(dateFallback); parsed != nil {
					event.EventDate = parsed
				}
			}

			result = append(result, event)
		}

	} else if strings.Contains(subject, "spamhaus-bots") || strings.Contains(body, "malware") {
		event, err := extractInfoMalware(eventTemplate, rows, dateFallback)
		if err != nil {
			return nil, err
		}
		result = append(result, event)

	} else {
		return nil, fmt.Errorf("unknown report type: %s", body)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
