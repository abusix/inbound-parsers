package cogent

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	pkgemail "github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var asnMatcher = regexp.MustCompile(`AS\d{5}`)

func NewParser() *Parser {
	return &Parser{}
}

// Parse implements the Cogent parser
// This is a complex parser that handles multiple report types:
// 1. IODEF/XML reports (gzipped) - NOT FULLY IMPLEMENTED YET
// 2. Simple phishing reports
// 3. IP reclamation reports
func (p *Parser) Parse(serializedEmail *pkgemail.SerializedEmail) ([]*events.Event, error) {
	subject, _ := common.GetSubject(serializedEmail, false)

	// Try to find XML part (IODEF reports)
	xmlPart, err := getXMLPart(serializedEmail)
	if err != nil {
		// No XML part found, try alternative formats

		// Check for simple phishing report
		if strings.Contains(strings.ToLower(subject), "phish on") {
			return parsePhishing(serializedEmail, subject)
		}

		// Try IP reclamation format
		return parseIPReclamation(subject, serializedEmail)
	}

	// Handle IODEF XML reports
	return parseIODEFReport(xmlPart, serializedEmail)
}

// getXMLPart finds the XML attachment in the email
func getXMLPart(serializedEmail *pkgemail.SerializedEmail) (*pkgemail.EmailPart, error) {
	for i := range serializedEmail.Parts {
		part := &serializedEmail.Parts[i]
		if part.Headers != nil {
			if contentType, ok := part.Headers["content-type"]; ok {
				for _, ct := range contentType {
					if strings.Contains(strings.ToLower(ct), "xml") {
						return part, nil
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("no XML part found")
}

// parsePhishing handles simple phishing reports
// Subject format: "phish on <IP>"
func parsePhishing(serializedEmail *pkgemail.SerializedEmail, subject string) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	url := strings.TrimSpace(strings.ReplaceAll(body, "\r\n", ""))

	event := events.NewEvent("cogent")
	event.EventTypes = []events.EventType{events.NewPhishing()}
	event.URL = url

	// Parse date from headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		if parsed := pkgemail.ParseDate(dateHeader[0]); parsed != nil {
			event.EventDate = parsed
		}
	}

	// Extract IP from subject (it's used as IP in Python version)
	event.IP = subject

	return []*events.Event{event}, nil
}

// parseIPReclamation handles IP reclamation reports
func parseIPReclamation(subject string, serializedEmail *pkgemail.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, fmt.Errorf("error getting body: %w", err)
	}

	// Find ASN in body
	asnMatch := asnMatcher.FindString(body)
	if asnMatch == "" {
		return nil, fmt.Errorf("ASN not found, report format changed")
	}

	// Parse external ID from subject
	externalID := ""
	if parts := strings.Split(subject, " - "); len(parts) > 0 {
		externalID = parts[0]
	}

	// Parse date
	var eventDate *string
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		if parsed := pkgemail.ParseDate(dateHeader[0]); parsed != nil {
			dateStr := parsed.Format("2006-01-02T15:04:05Z07:00")
			eventDate = &dateStr
		}
	}

	// Extract IPs from block after ASN
	var result []*events.Event
	lines := common.GetBlockAround(body, asnMatch)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed == asnMatch {
			continue
		}

		// Try to extract IP from line
		ip := common.ExtractOneIP(trimmed)
		if ip == "" {
			continue
		}

		event := events.NewEvent("cogent")

		// Add IP reclamation event type - using Exploit as placeholder since IPReclamation doesn't exist
		// TODO: Add IPReclamation event type when it's implemented
		event.EventTypes = []events.EventType{events.NewExploit()}

		// Add ASN detail
		event.AddEventDetail(&events.ASN{
			ASN: asnMatch,
		})

		// Add external ID
		if externalID != "" {
			event.AddEventDetail(&events.ExternalID{
				ID: externalID,
			})
		}

		event.IP = ip
		if eventDate != nil {
			if parsed := pkgemail.ParseDate(*eventDate); parsed != nil {
				event.EventDate = parsed
			}
		}

		result = append(result, event)
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no IPs found in reclamation report")
	}

	return result, nil
}

// parseIODEFReport handles IODEF XML reports
func parseIODEFReport(xmlPart *pkgemail.EmailPart, serializedEmail *pkgemail.SerializedEmail) ([]*events.Event, error) {
	// Get the body (may be gzipped)
	var xmlBody []byte

	switch body := xmlPart.Body.(type) {
	case string:
		xmlBody = []byte(body)
	case []byte:
		xmlBody = body
	default:
		return nil, fmt.Errorf("unexpected XML part body type: %T", body)
	}

	// Try to decompress if gzipped
	if len(xmlBody) > 2 && xmlBody[0] == 0x1f && xmlBody[1] == 0x8b {
		reader, err := gzip.NewReader(strings.NewReader(string(xmlBody)))
		if err != nil {
			// If it fails, fall back to IP reclamation parsing
			subject, _ := common.GetSubject(serializedEmail, false)
			return parseIPReclamation(subject, serializedEmail)
		}
		defer reader.Close()

		decompressed, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress XML: %w", err)
		}
		xmlBody = decompressed
	}

	// TODO: Implement full IODEF parsing
	// For now, extract basic information from XML/JSON
	return parseXMLContent(xmlBody, serializedEmail)
}

// parseXMLContent extracts events from XML content
func parseXMLContent(xmlBody []byte, serializedEmail *pkgemail.SerializedEmail) ([]*events.Event, error) {
	xmlStr := string(xmlBody)

	// Extract IP from XML
	ipRegex := regexp.MustCompile(`ipv.-addr">(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})<`)
	var ip string
	if matches := ipRegex.FindStringSubmatch(xmlStr); len(matches) > 1 {
		ip = common.ExtractOneIP(matches[1])
	}

	// Extract DateTime from XML
	dateRegex := regexp.MustCompile(`<DateTime>([^<]*)</DateTime>`)
	var eventDate *string
	if matches := dateRegex.FindStringSubmatch(xmlStr); len(matches) > 1 {
		if parsed := pkgemail.ParseDate(matches[1]); parsed != nil {
			dateStr := parsed.Format("2006-01-02T15:04:05Z07:00")
			eventDate = &dateStr
		}
	}

	// Try to extract JSON data from RecordData
	recordRegex := regexp.MustCompile(`<RecordData[^>]*>([^<]+)</RecordData>`)

	var allEvents []*events.Event

	if matches := recordRegex.FindAllStringSubmatch(xmlStr, -1); len(matches) > 0 {
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}

			var jsonData map[string]interface{}
			if err := json.Unmarshal([]byte(match[1]), &jsonData); err != nil {
				// Not valid JSON, skip
				continue
			}

			// Determine event type from Impact
			eventType := determineEventType(jsonData, xmlStr)

			event := events.NewEvent("cogent")

			// Set IP
			if ip != "" {
				event.IP = ip
			}
			parseIPFromJSON(event, jsonData)

			// Set date
			if eventDate != nil {
				if parsed := pkgemail.ParseDate(*eventDate); parsed != nil {
					event.EventDate = parsed
				}
			}
			parseDateFromJSON(event, jsonData)

			// Set event type and parse type-specific fields
			switch eventType {
			case "spam":
				parseSpamEvent(event, jsonData)
			case "phishing":
				parsePhishingEvent(event, jsonData)
			case "copyright":
				parseCopyrightEvent(event, jsonData)
			case "login_attack":
				parseLoginAttackEvent(event, jsonData)
			case "exploit":
				parseExploitEvent(event, jsonData)
			default:
				// Unknown type, use exploit as fallback
				event.EventTypes = []events.EventType{events.NewExploit()}
			}

			allEvents = append(allEvents, event)
		}
	}

	if len(allEvents) == 0 {
		return nil, fmt.Errorf("no events found in IODEF report")
	}

	return allEvents, nil
}

// determineEventType determines the event type from JSON data
func determineEventType(jsonData map[string]interface{}, xmlStr string) string {
	// Try to get type from various fields
	if typeStr, ok := jsonData["Type"].(string); ok {
		typeStr = strings.ToUpper(typeStr)

		if typeStr == "DMCA_COPYRIGHT" {
			return "copyright"
		}
		if typeStr == "SPAM" {
			return "spam"
		}
		if strings.Contains(typeStr, "PHISHING") {
			return "phishing"
		}
		if strings.ToLower(typeStr) == "exploited_compromised" {
			return "exploit"
		}
		if typeStr == "UNAUTHORIZED_ACCESS_ATTEMPT" || typeStr == "MALICIOUS_CONTENT" {
			if strings.Contains(xmlStr, "attack") {
				return "login_attack"
			}
		}
	}

	return "unknown"
}

// parseIPFromJSON extracts IP from JSON data
func parseIPFromJSON(event *events.Event, jsonData map[string]interface{}) {
	if event.IP != "" {
		return
	}

	// Try Source-IP
	if sourceIP, ok := jsonData["Source-IP"].(string); ok {
		event.IP = common.ExtractOneIP(sourceIP)
		return
	}

	// Try Source.IP_Address
	if source, ok := jsonData["Source"].(map[string]interface{}); ok {
		if ipAddr, ok := source["IP_Address"].(string); ok {
			event.IP = common.ExtractOneIP(ipAddr)
			return
		}
	}

	// Try Ip field
	if ipField, ok := jsonData["Ip"].(string); ok {
		event.IP = common.ExtractOneIP(ipField)
		return
	}
}

// parseDateFromJSON extracts date from JSON data
func parseDateFromJSON(event *events.Event, jsonData map[string]interface{}) {
	if event.EventDate != nil {
		return
	}

	// Try Date field
	if dateStr, ok := jsonData["Date"].(string); ok {
		if parsed := pkgemail.ParseDate(dateStr); parsed != nil {
			event.EventDate = parsed
			return
		}
	}

	// Try Source.TimeStamp
	if source, ok := jsonData["Source"].(map[string]interface{}); ok {
		if timestamp, ok := source["TimeStamp"].(string); ok {
			if parsed := pkgemail.ParseDate(timestamp); parsed != nil {
				event.EventDate = parsed
				return
			}
		}
	}

	// Try Content.Item.TimeStamp
	if content, ok := jsonData["Content"].(map[string]interface{}); ok {
		if item, ok := content["Item"].(map[string]interface{}); ok {
			if timestamp, ok := item["TimeStamp"].(string); ok {
				if parsed := pkgemail.ParseDate(timestamp); parsed != nil {
					event.EventDate = parsed
					return
				}
			}
		}
	}
}

// parseSpamEvent parses spam-specific fields
func parseSpamEvent(event *events.Event, jsonData map[string]interface{}) {
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Try Received-Date
	if receivedDate, ok := jsonData["Received-Date"].(string); ok {
		if parsed := pkgemail.ParseDate(receivedDate); parsed != nil {
			event.EventDate = parsed
		}
	}

	// Add evidence if present
	if evidence, ok := jsonData["evidence"].(map[string]interface{}); ok {
		if event.Headers == nil {
			event.Headers = make(map[string]interface{})
		}
		for k, v := range evidence {
			event.Headers[k] = v
		}
	}
}

// parsePhishingEvent parses phishing-specific fields
func parsePhishingEvent(event *events.Event, jsonData map[string]interface{}) {
	phishing := events.NewPhishing()

	// Set phishing URL
	if source, ok := jsonData["Source"].(string); ok {
		phishing.PhishingTarget = source
		event.URL = source
	}

	event.EventTypes = []events.EventType{phishing}

	// Port
	if port, ok := jsonData["Port"].(float64); ok {
		event.Port = int(port)
	} else if portStr, ok := jsonData["Port"].(string); ok {
		if p, err := common.ParsePort(portStr); err == nil {
			event.Port = p
		}
	}

	// Sender email
	if reportedFrom, ok := jsonData["Reported-From"].(string); ok {
		event.SenderEmail = reportedFrom
	}

	// Report ID
	if reportID, ok := jsonData["Report-ID"].(string); ok {
		event.AddEventDetail(&events.ExternalID{ID: reportID})
	}
}

// parseCopyrightEvent parses copyright-specific fields
func parseCopyrightEvent(event *events.Event, jsonData map[string]interface{}) {
	var work, protocol string
	var port int

	// Extract from Source
	if source, ok := jsonData["Source"].(map[string]interface{}); ok {
		if typeStr, ok := source["Type"].(string); ok {
			protocol = typeStr
		}
		if portNum, ok := source["Port"].(float64); ok {
			port = int(portNum)
		}
	}

	// Extract from Content.Item
	if content, ok := jsonData["Content"].(map[string]interface{}); ok {
		if item, ok := content["Item"].(map[string]interface{}); ok {
			if title, ok := item["Title"].(string); ok {
				work = title
			}

			// Add file details
			if fileName, ok := item["FileName"].(string); ok {
				fileDetail := &events.File{
					FileName: fileName,
				}
				if fileSize, ok := item["FileSize"].(string); ok {
					fileDetail.FileSize = fileSize
				}
				if hash, ok := item["Hash"].(string); ok {
					fileDetail.FileHash = hash
				}
				event.AddEventDetail(fileDetail)
			}
		}
	}

	event.EventTypes = []events.EventType{events.NewCopyright(work, "", protocol)}
	event.Port = port
}

// parseLoginAttackEvent parses login attack-specific fields
func parseLoginAttackEvent(event *events.Event, jsonData map[string]interface{}) {
	event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
}

// parseExploitEvent parses exploit-specific fields
func parseExploitEvent(event *events.Event, jsonData map[string]interface{}) {
	event.EventTypes = []events.EventType{events.NewExploit()}

	// Port
	if port, ok := jsonData["Port"].(float64); ok {
		event.Port = int(port)
	} else if portStr, ok := jsonData["Port"].(string); ok {
		if p, err := common.ParsePort(portStr); err == nil {
			event.Port = p
		}
	}

	// Report ID
	if reportID, ok := jsonData["Report-ID"].(string); ok {
		event.AddEventDetail(&events.ExternalID{ID: reportID})
	}
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
