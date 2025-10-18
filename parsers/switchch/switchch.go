package switchch

import (
	"encoding/json"
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

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	bodyLower := strings.ToLower(common.RemoveCarriageReturn(body))

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	var eventsList []*events.Event

	// Check for SWITCH-CERT Report with JSON data
	if strings.Contains(subject, "SWITCH-CERT Report") {
		if len(serializedEmail.Parts) < 2 {
			return nil, common.NewParserError("expected JSON attachment not found")
		}

		jsonPart := serializedEmail.Parts[1]
		var jsonPartBody string

		// Check if part is zipped
		var contentType string
		if jsonPart.Headers != nil {
			if ct, ok := jsonPart.Headers["content-type"]; ok && len(ct) > 0 {
				contentType = strings.ToLower(ct[0])
			}
		}

		if strings.Contains(contentType, "zip") {
			jsonPartBody, err = common.HandleZipPart(jsonPart.Body)
			if err != nil {
				return nil, err
			}
		} else {
			switch body := jsonPart.Body.(type) {
			case string:
				jsonPartBody = body
			case []byte:
				jsonPartBody = string(body)
			default:
				return nil, fmt.Errorf("unexpected JSON part body type: %T", jsonPart.Body)
			}
		}

		// Parse JSON array
		var entries []map[string]interface{}
		if err := json.Unmarshal([]byte(jsonPartBody), &entries); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}

		for _, entry := range entries {
			event, err := p.parseJSONEntry(entry, serializedEmail)
			if err != nil {
				return nil, err
			}
			eventsList = append(eventsList, event)
		}

		return eventsList, nil
	}

	// Check for Phishing reports
	if strings.Contains(subject, "Phishing") {
		marker := "\nhxxp"
		startIndex := strings.Index(bodyLower, marker)
		if startIndex == -1 {
			return nil, common.NewParserError("phishing URLs not found in body")
		}

		endIndex := strings.Index(bodyLower[startIndex:], "\n\n\n")
		if endIndex == -1 {
			endIndex = len(bodyLower)
		} else {
			endIndex += startIndex
		}

		lines := strings.Split(strings.TrimSpace(bodyLower[startIndex:endIndex]), "\n")
		for _, line := range lines {
			parts := strings.Fields(line)
			if len(parts) == 0 {
				continue
			}

			url := common.CleanURL(parts[0])
			if strings.HasPrefix(url, "http") {
				event := events.NewEvent("switchch")
				event.URL = url
				event.IP = line // Store entire line as IP field (as per Python)
				event.EventTypes = []events.EventType{events.NewPhishing()}

				if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
					event.EventDate = email.ParseDate(dateHeaders[0])
				}

				eventsList = append(eventsList, event)
			}
		}

		return eventsList, nil
	}

	// Check for "Misuse of your website" reports
	if strings.Contains(subject, "Misuse of your website") {
		event := events.NewEvent("switchch")
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}

		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}

		url := common.FindStringWithoutMarkers(bodyLower, "that the website", "is being misused for")
		event.URL = url

		return []*events.Event{event}, nil
	}

	// Check for SSH brute-force reports
	if strings.Contains(subjectLower, "ssh brute-force") {
		event := events.NewEvent("switchch")
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

		eventDateStr := common.FindStringWithoutMarkers(bodyLower, "suspicious activity on", "(")
		eventDateStr = strings.TrimSpace(eventDateStr)

		// Parse date in format "2006/Jan/02 15:04:05"
		if eventDateStr != "" {
			parsedDate, err := time.Parse("2006/Jan/02 15:04:05", eventDateStr)
			if err == nil {
				event.EventDate = &parsedDate
			}
		}

		event.URL = body

		return []*events.Event{event}, nil
	}

	return nil, common.NewNewTypeError(subject)
}

func (p *Parser) parseJSONEntry(entry map[string]interface{}, serializedEmail *email.SerializedEmail) (*events.Event, error) {
	// Extract classification type
	eventTypeRaw, ok := entry["classification.type"]
	if !ok {
		return nil, common.NewParserError("Json format changed, adapt the parser")
	}
	eventType := strings.ReplaceAll(fmt.Sprintf("%v", eventTypeRaw), " ", "-")

	// Extract classification identifier (optional)
	var eventTypeInfo string
	if val, ok := entry["classification.identifier"]; ok && val != nil {
		eventTypeInfo = fmt.Sprintf("%v", val)
	}

	// Extract fields
	sourceAsName := getStringField(entry, "source.as_name")
	sourceASN := getStringField(entry, "source.asn")
	sourceIP := getStringField(entry, "source.ip")
	sourcePort := getIntField(entry, "source.port")
	destinationAsName := getStringField(entry, "destination.as_name")
	destinationASN := getStringField(entry, "destination.asn")
	destinationIP := getStringField(entry, "destination.ip")
	destinationPort := getIntField(entry, "destination.port")
	transportProtocol := getStringField(entry, "protocol.transport")
	dateStr := getStringField(entry, "time.source")

	event := events.NewEvent("switchch")

	// Determine event type
	eventTypeInfoLower := strings.ToLower(eventTypeInfo)
	eventTypeLower := strings.ToLower(eventType)

	if strings.Contains(eventTypeLower, "brute-force") && strings.Contains(eventTypeInfoLower, "ssh") {
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	} else if strings.Contains(eventTypeLower, "infected-system") || strings.Contains(eventTypeLower, "ransomware") {
		event.EventTypes = []events.EventType{events.NewMalware(eventTypeInfo)}
		if strings.Contains(eventTypeInfoLower, "bot") {
			event.EventTypes = []events.EventType{events.NewBot("")}
		}
	} else if strings.Contains(eventTypeLower, "vulnerable-system") || strings.Contains(eventTypeLower, "vulnerable-service") {
		if eventTypeInfo == "vulnerable" {
			event.EventTypes = []events.EventType{events.NewOpen("service")}
		} else {
			service := common.MapServiceStrings(eventTypeInfo)
			event.EventTypes = []events.EventType{events.NewOpen(service)}
		}
	} else if strings.Contains(eventTypeLower, "spam") {
		event.EventTypes = []events.EventType{events.NewSpam()}
	} else if strings.Contains(eventTypeInfoLower, "accessible") {
		serviceParts := strings.SplitN(eventTypeInfo, "-", 2)
		service := eventTypeInfo
		if len(serviceParts) > 1 {
			service = serviceParts[1]
		}
		service = common.MapServiceStrings(service)
		// Create Open event type (LOW severity not supported in current Go implementation)
		event.EventTypes = []events.EventType{events.NewOpen(service)}
	} else if (strings.Contains(eventTypeLower, "compromised") &&
		strings.Contains(eventTypeInfoLower, "webshell")) ||
		strings.Contains(eventTypeInfoLower, "ssl") {
		event.EventTypes = []events.EventType{events.NewCompromisedServer()}
	} else {
		return nil, common.NewNewTypeError(fmt.Sprintf("%s/%s", eventType, eventTypeInfo))
	}

	// Set event date
	if dateStr != "" {
		event.EventDate = email.ParseDate(dateStr)
	} else {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Set source information
	event.IP = sourceIP
	event.Port = sourcePort

	// Add source AS information
	if sourceASN != "" || sourceAsName != "" {
		sourceAS := &events.ASN{
			ASN:    sourceASN,
			ASName: sourceAsName,
		}
		event.AddEventDetail(sourceAS)
	}

	// Add target AS information
	if destinationASN != "" || destinationAsName != "" {
		targetAS := &events.ASN{
			ASN:    destinationASN,
			ASName: destinationAsName,
		}
		event.AddEventDetail(targetAS)
	}

	// Add target information
	if destinationIP != "" || destinationPort != 0 {
		target := &events.Target{
			IP: destinationIP,
		}
		if destinationPort != 0 {
			target.Port = strconv.Itoa(destinationPort)
		}
		event.AddEventDetail(target)
	}

	// Add transport protocol
	if transportProtocol != "" {
		protocol := &events.TransportProtocol{
			Protocol: transportProtocol,
		}
		event.AddEventDetail(protocol)
	}

	return event, nil
}

// Helper functions to extract typed fields from JSON map
func getStringField(entry map[string]interface{}, key string) string {
	if val, ok := entry[key]; ok && val != nil {
		return fmt.Sprintf("%v", val)
	}
	return ""
}

func getIntField(entry map[string]interface{}, key string) int {
	if val, ok := entry[key]; ok && val != nil {
		switch v := val.(type) {
		case float64:
			return int(v)
		case int:
			return v
		case string:
			if i, err := strconv.Atoi(v); err == nil {
				return i
			}
		}
	}
	return 0
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
