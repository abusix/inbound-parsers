package csirt_muni

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

const (
	digitalOceanResponse = "Thank you for your report. Please note that this is an automated mailbox and is not directly monitored."
)

var (
	testStrings = []string{
		"the security team CSIRT-MU detected invol",
		"the security team CSIRT-MU has detected involvement",
	}
	htmlCleanerRegex = regexp.MustCompile(`<.*?>`)
	colonKeyValueRegex = regexp.MustCompile(`(\w+):\s*(.*)[\r\n]?`)
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	if body == "" {
		return []*events.Event{}, nil
	}

	// Get the English subject (after "/ ")
	subject, _ := common.GetSubject(serializedEmail, false)
	englishSubject := subject
	if parts := strings.Split(subject, "/ "); len(parts) > 1 {
		englishSubject = parts[len(parts)-1]
	}

	// Check if this is multipart (HTML) or plain text
	isMultipart := false
	if len(serializedEmail.Parts) > 0 {
		for _, part := range serializedEmail.Parts {
			if part.ContentType != "" && strings.Contains(part.ContentType, "html") {
				isMultipart = true
				break
			}
		}
	}

	if isMultipart {
		return parseHTML(serializedEmail, body, englishSubject, false)
	}
	return parsePlain(serializedEmail, body, englishSubject)
}

func parseHTML(serializedEmail *email.SerializedEmail, body, subject string, stop bool) ([]*events.Event, error) {
	event := events.NewEvent("csirt_muni")

	// Find the start of the data section
	startIndex := -1
	for _, test := range testStrings {
		startIndex = strings.Index(body, test)
		if startIndex != -1 {
			break
		}
	}

	// If not found, try alternative part
	if startIndex == -1 {
		if stop {
			return nil, common.NewParserError("could not find data part")
		}
		// Try to get the alternative part (index 1)
		if len(serializedEmail.Parts) > 1 {
			otherBody, ok := serializedEmail.Parts[1].Body.(string)
			if !ok {
				if bodyBytes, ok := serializedEmail.Parts[1].Body.([]byte); ok {
					otherBody = string(bodyBytes)
				} else {
					return nil, common.NewParserError("could not find data part")
				}
			}
			otherCandidate := removeHTML(otherBody)
			return parseHTML(serializedEmail, otherCandidate, subject, true)
		}
		return nil, common.NewParserError("could not find data part")
	}

	dataPart := body[startIndex:]

	// Extract date
	date := common.FindStringWithoutMarkers(dataPart, "Time of detection:", "")
	date = strings.TrimSpace(date)
	if parsedDate := email.ParseDate(date); parsedDate != nil {
		event.EventDate = parsedDate
	} else {
		// Fall back to email header date
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
				event.EventDate = parsedDate
			}
		}
	}

	// Extract IP
	ipStr := common.FindStringWithoutMarkers(dataPart, "IP address:", "")
	if extractedIP := common.ExtractOneIP(ipStr); extractedIP != "" {
		event.IP = extractedIP
	}
	if event.IP == "" {
		event.IP = subject
	}

	// Extract domain
	domain := common.FindStringWithoutMarkers(dataPart, "Domain name:", "")
	domain = strings.Trim(domain, " -")
	if domain != "" {
		event.URL = domain
	}

	// Determine event type from incident identifier
	incidentIdentifier := common.FindStringWithoutMarkers(dataPart, "Incident", "\n")
	incidentIdentifier = strings.ToLower(strings.TrimSpace(incidentIdentifier))

	if strings.Contains(incidentIdentifier, "port") || strings.Contains(incidentIdentifier, "sip scan attacks") {
		event.EventTypes = []events.EventType{events.NewPortScan()}
	} else if strings.Contains(incidentIdentifier, "traffic") && strings.Contains(incidentIdentifier, "anomalous") {
		event.EventTypes = []events.EventType{events.NewExploit()}
	} else if strings.Contains(incidentIdentifier, "honeypot") {
		event.EventTypes = []events.EventType{events.NewWebHack()}
	} else if strings.Contains(incidentIdentifier, "brute force") {
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	} else if strings.Contains(incidentIdentifier, "active scanning") {
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
	} else {
		return nil, common.NewNewTypeError(incidentIdentifier)
	}

	return []*events.Event{event}, nil
}

func parsePlain(serializedEmail *email.SerializedEmail, body, subject string) ([]*events.Event, error) {
	event := events.NewEvent("csirt_muni")

	// Parse colon-separated key-value pairs
	for key, value := range colonKeyValueGenerator(body) {
		switch strings.ToLower(key) {
		case "address":
			if extractedIP := common.ExtractOneIP(value); extractedIP != "" {
				event.IP = extractedIP
			}
		case "detection":
			if parsedDate := email.ParseDate(value); parsedDate != nil {
				event.EventDate = parsedDate
			}
		case "name":
			if value != "---" {
				event.URL = value
			}
		case "incident":
			if strings.Contains(value, "Incident type") {
				valueLower := strings.ToLower(value)
				if strings.Contains(valueLower, "sip scan attacks") || strings.Contains(valueLower, "port scanning") {
					event.EventTypes = []events.EventType{events.NewPortScan()}
				} else if strings.Contains(valueLower, "ssh brute force attacks") {
					event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
				} else if strings.Contains(valueLower, "anomalous telnet traffic") {
					event.EventTypes = []events.EventType{events.NewExploit()}
				} else {
					return nil, common.NewNewTypeError(value)
				}
			}
		}
	}

	return []*events.Event{event}, nil
}

// removeHTML removes HTML tags from a string
func removeHTML(rawHTML string) string {
	return htmlCleanerRegex.ReplaceAllString(rawHTML, "")
}

// colonKeyValueGenerator extracts key-value pairs from colon-separated text
func colonKeyValueGenerator(text string) map[string]string {
	result := make(map[string]string)
	matches := colonKeyValueRegex.FindAllStringSubmatch(text, -1)
	for _, match := range matches {
		if len(match) == 3 {
			key := strings.TrimSpace(match[1])
			value := strings.TrimSpace(match[2])
			result[key] = value
		}
	}
	return result
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
