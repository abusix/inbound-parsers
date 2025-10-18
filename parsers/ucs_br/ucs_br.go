package ucs_br

import (
	"encoding/csv"
	"fmt"
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/parsers/common"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Extract body from parts[1]
	if len(serializedEmail.Parts) < 2 {
		return nil, fmt.Errorf("body not found - expected at least 2 parts")
	}

	var body string
	switch b := serializedEmail.Parts[1].Body.(type) {
	case string:
		body = b
	case []byte:
		body = string(b)
	default:
		return nil, fmt.Errorf("unexpected body type: %T", serializedEmail.Parts[1].Body)
	}

	var csvData []map[string]string
	var err error

	// Try to extract HTML table as CSV first
	csvLines, tableErr := common.ExtractHTMLTableAsCSV(body)
	if tableErr == nil && len(csvLines) > 0 {
		// Successfully extracted table, parse it
		csvData, err = parseCSVLines(csvLines)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CSV from HTML table: %w", err)
		}
	} else {
		// Fall back to text extraction
		csvData, err = extractLogsFromText(body)
		if err != nil {
			return nil, fmt.Errorf("failed to extract logs: %w", err)
		}
	}

	// Track unique IP:Port combinations to avoid duplicates
	seen := make(map[string]bool)
	var result []*events.Event

	for _, row := range csvData {
		sourceIP := row["source address"]
		sourcePort := row["source port"]
		targetIP := row["destination address"]
		targetPort := row["destination port"]
		protocol := row["ip protocol"]
		receiveTime := row["receive time"]

		// Create unique key for deduplication
		key := fmt.Sprintf("%s:%s-%s:%s", sourceIP, sourcePort, targetIP, targetPort)
		if seen[key] {
			continue
		}
		seen[key] = true

		event := events.NewEvent("ucs_br")
		event.EventTypes = []events.EventType{events.NewCompromisedServer()}

		// Set event date with UTC-3 timezone
		if receiveTime != "" {
			eventDateStr := receiveTime + " -03:00"
			event.EventDate = email.ParseDate(eventDateStr)
		}

		event.IP = sourceIP
		if sourcePort != "" {
			if port, err := common.ParsePort(sourcePort); err == nil {
				event.Port = port
			}
		}

		// Add target information
		event.AddEventDetail(&events.Target{
			IP:   targetIP,
			Port: targetPort,
		})

		// Add transport protocol
		if protocol != "" {
			event.AddEventDetail(&events.TransportProtocol{
				Protocol: protocol,
			})
		}

		result = append(result, event)
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no events extracted from email")
	}

	return result, nil
}

// parseCSVLines parses CSV lines into maps with lowercase keys
func parseCSVLines(csvLines []string) ([]map[string]string, error) {
	if len(csvLines) == 0 {
		return nil, fmt.Errorf("no CSV lines provided")
	}

	reader := csv.NewReader(strings.NewReader(strings.Join(csvLines, "\n")))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSV: %w", err)
	}

	if len(records) < 2 {
		return nil, fmt.Errorf("CSV has no data rows")
	}

	// Get headers and lowercase them
	headers := records[0]
	for i := range headers {
		headers[i] = strings.ToLower(strings.TrimSpace(headers[i]))
	}

	// Convert records to maps
	var result []map[string]string
	for i := 1; i < len(records); i++ {
		row := make(map[string]string)
		for j, value := range records[i] {
			if j < len(headers) {
				row[headers[j]] = strings.TrimSpace(value)
			}
		}
		result = append(result, row)
	}

	return result, nil
}

// extractLogsFromText extracts logs from the text format when HTML table extraction fails
func extractLogsFromText(body string) ([]map[string]string, error) {
	// Clean up the body
	bodyRaw := strings.ReplaceAll(body, "<br>", "\n")
	bodyRaw = strings.ToLower(bodyRaw)

	// Remove HTML tags
	htmlTagRe := regexp.MustCompile(`<[^>]+>`)
	bodyRaw = htmlTagRe.ReplaceAllString(bodyRaw, "")

	// Find the logs section
	parts := strings.Split(bodyRaw, "logs - all times are utc-3")
	if len(parts) < 2 {
		return nil, fmt.Errorf("logs section not found")
	}

	// Get the logs section up to the next double newline
	logsSections := strings.Split(parts[1], "\n\n")
	if len(logsSections) == 0 {
		return nil, fmt.Errorf("empty logs section")
	}

	logs := strings.TrimSpace(logsSections[0])
	logs = strings.ReplaceAll(logs, "\t", "")
	logs = strings.ReplaceAll(logs, "\xa0", "")
	logs = strings.ReplaceAll(logs, "\u00a0", "") // non-breaking space

	// Clean up multiple spaces after commas
	commaSpaceRe := regexp.MustCompile(`,\s+`)
	logs = commaSpaceRe.ReplaceAllString(logs, ",")

	// Parse as CSV
	reader := csv.NewReader(strings.NewReader(logs))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse logs as CSV: %w", err)
	}

	if len(records) < 2 {
		return nil, fmt.Errorf("logs CSV has no data rows")
	}

	// Get headers and lowercase them
	headers := records[0]
	for i := range headers {
		headers[i] = strings.ToLower(strings.TrimSpace(headers[i]))
	}

	// Convert to maps
	var result []map[string]string
	for i := 1; i < len(records); i++ {
		row := make(map[string]string)
		for j, value := range records[i] {
			if j < len(headers) {
				row[headers[j]] = strings.TrimSpace(value)
			}
		}
		result = append(result, row)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
