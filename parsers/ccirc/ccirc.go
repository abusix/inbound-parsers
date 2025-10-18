package ccirc

import (
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// parseDateTime attempts to parse various datetime formats
func parseDateTime(dateStr string) *time.Time {
	dateStr = strings.TrimSpace(dateStr)
	if dateStr == "" {
		return nil
	}

	// Common formats used in CCIRC reports
	formats := []string{
		time.RFC3339,                // "2006-01-02T15:04:05Z07:00"
		"2006-01-02 15:04:05",       // "2024-10-18 14:30:00"
		"2006-01-02 15:04:05 MST",   // "2024-10-18 14:30:00 UTC"
		"2006-01-02 15:04:05 -0700", // "2024-10-18 14:30:00 -0400"
		"2006-01-02T15:04:05",       // "2024-10-18T14:30:00"
		"02/01/2006 15:04:05",       // "18/10/2024 14:30:00"
		"01/02/2006 15:04:05",       // "10/18/2024 14:30:00"
		"2006-01-02",                // "2024-10-18"
		time.RFC1123Z,               // Email format
		time.RFC1123,                // Email format with zone name
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return &t
		}
	}

	// Try email.ParseDate as fallback (handles more email-specific formats)
	return email.ParseDate(dateStr)
}

// getParserData extracts CSV header and entries from the email body
func getParserData(body string) (string, [][]string, error) {
	// Find start of entries - look for first line break
	startOfEntries := strings.Index(body, "\r\n")
	isSimpleLinebreak := false
	if startOfEntries == -1 {
		startOfEntries = strings.Index(body, "\n")
		isSimpleLinebreak = true
	}
	if startOfEntries == -1 {
		return "", nil, fmt.Errorf("start of entries not found in ccirc")
	}

	// Find start of header (after double newline)
	startOfHeader := strings.LastIndex(body[:startOfEntries], "\n\n")
	if startOfHeader < 0 {
		startOfHeader = -2
	}
	header := body[startOfHeader+2 : startOfEntries]

	// Find end of entries
	endOfEntries := strings.LastIndex(body, "\r\n")
	if endOfEntries == -1 {
		endOfEntries = strings.LastIndex(body, "\n")
	}
	if endOfEntries == -1 {
		return "", nil, fmt.Errorf("end of entries not found in ccirc")
	}

	// Extract entries string
	var entriesString string
	if isSimpleLinebreak {
		entriesString = body[startOfEntries+1 : endOfEntries]
	} else {
		entriesString = body[startOfEntries+2 : endOfEntries]
	}

	// Parse CSV
	reader := csv.NewReader(strings.NewReader(entriesString))
	entries, err := reader.ReadAll()
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse CSV: %w", err)
	}

	return header, entries, nil
}

// mapServiceStrings normalizes service names (simplified version)
func mapServiceStrings(service string) string {
	service = strings.ToLower(strings.TrimSpace(service))
	// Add more mappings as needed based on shadowserver patterns
	switch service {
	case "dns", "domain":
		return "dns"
	case "rdp", "remote desktop":
		return "rdp"
	case "ssh":
		return "ssh"
	case "telnet":
		return "telnet"
	default:
		return service
	}
}

// createEvent creates a single event from a CSV row
func createEvent(entry []string, header string) (*events.Event, error) {
	// Parse header and create entry map
	keys := strings.Split(header, ",")
	if len(entry) != len(keys) {
		return nil, fmt.Errorf("CSV entry length mismatch")
	}

	entryMap := make(map[string]string)
	for i, key := range keys {
		value := strings.TrimSpace(entry[i])
		if value != "" {
			entryMap[strings.TrimSpace(key)] = value
		}
	}

	event := events.NewEvent("ccirc")

	// Extract required fields
	typeStr, ok := entryMap["type"]
	if !ok || typeStr == "" {
		return nil, nil // Skip invalid entries
	}
	delete(entryMap, "type")

	// Parse event date
	if sourceTime, ok := entryMap["source time"]; ok {
		sourceTime = strings.TrimSpace(sourceTime)
		parsedDate := parseDateTime(sourceTime)
		if parsedDate != nil {
			event.EventDate = parsedDate
		}
		delete(entryMap, "source time")
	} else {
		return nil, nil // Skip entries without date
	}

	// Extract IP
	if ipStr, ok := entryMap["ip"]; ok {
		ipStr = strings.TrimSpace(ipStr)
		event.IP = ipStr
		delete(entryMap, "ip")
	} else {
		return nil, nil // Skip entries without IP
	}

	// Process remaining fields
	var malwareName, targetIP, targetPort string

	for key, value := range entryMap {
		value = strings.TrimSpace(strings.Trim(value, "-"))
		if value == "" {
			continue
		}

		switch strings.ToLower(key) {
		case "port":
			if port, err := strconv.Atoi(value); err == nil {
				event.Port = port
			}
		case "asn":
			event.AddEventDetail(&events.ASN{ASN: value})
		case "url":
			event.URL = common.CleanURL(value)
		case "uuid":
			event.AddEventDetail(&events.ExternalID{ID: value})
		case "destination ip":
			targetIP = value
		case "destination port":
			targetPort = value
		default:
			if strings.Contains(strings.ToLower(key), "malware") {
				malwareName = value
			}
		}
	}

	// Map type string to event types
	typeStr = strings.ToLower(strings.TrimSpace(typeStr))

	switch typeStr {
	case "vulnerable service", "open service":
		// Check for vulnerability field
		if vulnerability, ok := entryMap["vulnerability"]; ok {
			vulnerability = strings.ToLower(vulnerability)
			if strings.Contains(vulnerability, "open") {
				service := strings.TrimSpace(strings.Replace(vulnerability, "open", "", -1))
				event.EventTypes = []events.EventType{events.NewOpen(service)}
			} else if strings.Contains(vulnerability, "exposed") {
				service := strings.TrimSpace(strings.Replace(vulnerability, "exposed", "", -1))
				event.EventTypes = []events.EventType{events.NewOpen(service)}
			} else if strings.Contains(vulnerability, "obsolete service") {
				// Extract service from description
				if description, ok := entryMap["description"]; ok {
					service := common.FindStringWithoutMarkers(description, "(", ")")
					event.EventTypes = []events.EventType{events.NewOpen(mapServiceStrings(service))}
				} else {
					event.EventTypes = []events.EventType{events.NewOpen("unknown")}
				}
			} else if strings.Contains(vulnerability, "cve") {
				event.EventTypes = []events.EventType{events.NewCVE(vulnerability, "", "")}
			} else if strings.Contains(vulnerability, "recursive dns resolver") {
				event.EventTypes = []events.EventType{events.NewOpen("recursive_dns_resolver")}
			} else {
				// Try shadowserver type matching or default to Open with vulnerability as service
				event.EventTypes = []events.EventType{events.NewOpen(vulnerability)}
			}
		} else if protocol, ok := entryMap["protocol"]; ok {
			event.EventTypes = []events.EventType{events.NewOpen(mapServiceStrings(protocol))}
		} else if description, ok := entryMap["description"]; ok {
			event.EventTypes = []events.EventType{events.NewOpen(mapServiceStrings(description))}
		} else {
			event.EventTypes = []events.EventType{events.NewOpen("unknown")}
		}

	case "blacklist":
		event.EventTypes = []events.EventType{events.NewDNSBlocklist()}

	case "botnet drone":
		event.EventTypes = []events.EventType{events.NewMalware(malwareName)}

	case "spam infrastructure":
		event.EventTypes = []events.EventType{events.NewSpamvertised()}

	case "brute-force":
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

	case "phishing":
		event.EventTypes = []events.EventType{events.NewPhishing()}

	case "compromised server":
		event.EventTypes = []events.EventType{events.NewCompromisedServer()}

	case "scanner":
		event.EventTypes = []events.EventType{events.NewPortScan()}

	case "c&c":
		event.EventTypes = []events.EventType{events.NewBot("")}

	case "ddos infrastructure":
		event.EventTypes = []events.EventType{events.NewDDoS()}

	case "malware url":
		event.EventTypes = []events.EventType{events.NewMalware(malwareName)}

	case "ddos target":
		// Skip these events - they're not actionable
		return nil, nil

	default:
		// Unknown type - return error for visibility
		return nil, common.NewNewTypeError(typeStr)
	}

	// Add target information if present
	if targetIP != "" || targetPort != "" {
		event.AddEventDetail(&events.Target{
			IP:   targetIP,
			Port: targetPort,
		})
	}

	return event, nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Try to get body from attachment first (CSV file)
	var body string
	if len(serializedEmail.Parts) > 1 {
		// Check if second part has .csv in content-disposition
		if disposition, ok := serializedEmail.Parts[1].Headers["content-disposition"]; ok {
			if len(disposition) > 0 && strings.Contains(disposition[0], ".csv") {
				switch b := serializedEmail.Parts[1].Body.(type) {
				case string:
					body = b
				case []byte:
					body = string(b)
				}
			}
		}
	}

	// If no CSV attachment, try to get from body with base64 encoding
	if body == "" && len(serializedEmail.Parts) > 0 {
		part := serializedEmail.Parts[0]
		if part.Headers != nil {
			if transferEncodings, ok := part.Headers["content-transfer-encoding"]; ok {
				if len(transferEncodings) == 1 && transferEncodings[0] == "base64" {
					switch b := part.Body.(type) {
					case string:
						body = b
					case []byte:
						body = string(b)
					}
				}
			}
		}
	}

	// Fallback to regular body
	if body == "" {
		var err error
		body, err = common.GetBody(serializedEmail, false)
		if err != nil || body == "" {
			return nil, common.NewParserError("no email body found")
		}
	}

	// Parse CSV data
	header, entries, err := getParserData(body)
	if err != nil {
		return nil, err
	}

	// Process each entry
	var results []*events.Event
	var errors []error

	for _, entry := range entries {
		event, err := createEvent(entry, header)
		if err != nil {
			// Collect errors but continue processing
			errors = append(errors, err)
			continue
		}
		if event != nil {
			results = append(results, event)
		}
	}

	// If we have results, return them even if there were some errors
	if len(results) > 0 {
		return results, nil
	}

	// If no results and we have errors, return the first error
	if len(errors) > 0 {
		return nil, errors[0]
	}

	return nil, common.NewParserError("no valid events found")
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
