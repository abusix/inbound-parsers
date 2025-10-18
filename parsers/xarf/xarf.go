package xarf

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
	"gopkg.in/yaml.v3"
)

type Parser struct{}

var (
	ctSecure = []string{
		"multipart/signed",
		"multipart/encrypted",
		"application/pkcs7-mime",
		"message/rfc822",
	}
)

func NewParser() *Parser {
	return &Parser{}
}

// getXARFVersion determines the X-ARF version from headers and content type
func getXARFVersion(serializedEmail *email.SerializedEmail, contentType string) string {
	if xarf, ok := serializedEmail.Headers["x-xarf"]; ok && len(xarf) > 0 {
		xarfUpper := strings.ToUpper(xarf[0])
		if xarfUpper == "PLAIN" || xarfUpper == "YES" {
			if contentType == "multipart/mixed" {
				return "v0.2:PLAIN"
			}
		} else if xarfUpper == "SECURE" {
			for _, ct := range ctSecure {
				if contentType == ct {
					return "v0.2:SECURE"
				}
			}
		} else if xarfUpper == "BULK" {
			return "v0.2:BULK"
		}
	} else if xarf, ok := serializedEmail.Headers["x-arf"]; ok && len(xarf) > 0 {
		if strings.ToUpper(xarf[0]) == "YES" {
			if contentType == "multipart/mixed" {
				return "v0.1"
			}
		}
	}
	return ""
}

// getContentType extracts main content type from SerializedEmail
func getContentType(serializedEmail *email.SerializedEmail) string {
	if ct, ok := serializedEmail.Headers["content-type"]; ok && len(ct) > 0 {
		// Extract main type before semicolon
		parts := strings.Split(ct[0], ";")
		return strings.TrimSpace(strings.ToLower(parts[0]))
	}
	return ""
}

// looksLikeXARF checks if a part looks like an X-ARF report
func looksLikeXARF(part email.EmailPart) bool {
	if ct, ok := part.Headers["content-type"]; ok && len(ct) > 0 {
		// Check for name=report.txt in content-type
		if strings.Contains(strings.ToLower(ct[0]), "name=report.txt") {
			return true
		}
	}

	// Check content-disposition for filename=report.txt
	if disp, ok := part.Headers["content-disposition"]; ok && len(disp) > 0 {
		matched, _ := regexp.MatchString(`filename=['"]?report\.txt`, disp[0])
		return matched
	}

	return false
}

// addXARFContentRecursively adds XARF content to event headers recursively
func addXARFContentRecursively(content interface{}, event *events.Event, parentKey string) {
	switch v := content.(type) {
	case map[string]interface{}:
		for key, value := range v {
			combinedKey := key
			if parentKey != "" {
				combinedKey = parentKey + "_" + key
			}
			addXARFContentRecursively(value, event, combinedKey)
		}
	case []interface{}:
		for index, value := range v {
			combinedKey := fmt.Sprintf("%s_%d", parentKey, index)
			addXARFContentRecursively(value, event, combinedKey)
		}
	default:
		// Add to headers
		key := parentKey
		if key == "source-port" {
			key = "source_port"
		}
		if event.Headers == nil {
			event.Headers = make(map[string]interface{})
		}
		event.Headers[key] = content
	}
}

// addURL sets the event URL if source-type is uri
func addURL(event *events.Event, xarfContent map[string]interface{}) {
	if sourceType, ok := xarfContent["source-type"].(string); ok {
		if sourceType == "uri" {
			if source, ok := xarfContent["source"].(string); ok {
				event.URL = common.CleanURL(source)
			}
		}
	}
}

// cleanUserAgent cleans the User-Agent field in the report
func cleanUserAgent(report string) string {
	re := regexp.MustCompile(`User-Agent:\s+-\s+(.*)`)
	return re.ReplaceAllString(report, "User-Agent: $1")
}

// tryToFindTypeByAttachedDetail attempts to infer event type from attached details
func tryToFindTypeByAttachedDetail(part, subject string, event *events.Event) error {
	partLower := strings.ToLower(part)
	subjectLower := strings.ToLower(subject)

	if strings.Contains(partLower, "sshd") || strings.Contains(partLower, "login") || strings.Contains(partLower, "admin") {
		username := common.FindStringWithoutMarkers(part, "invalid user ", " ")
		username = strings.TrimSpace(username)
		if username != "" {
			event.EventTypes = []events.EventType{events.NewLoginAttack(username, "")}
		} else {
			event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
		}
		return nil
	} else if strings.Contains(subjectLower, "portscan") {
		event.EventTypes = []events.EventType{events.NewPortScan()}
		return nil
	} else if strings.Contains(subjectLower, "spam") {
		event.EventTypes = []events.EventType{events.NewSpam()}
		return nil
	} else if strings.Contains(subjectLower, "web") {
		event.EventTypes = []events.EventType{events.NewWebHack()}
		return nil
	} else if strings.Contains(subjectLower, "brute force") {
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
		return nil
	} else if strings.Contains(subjectLower, "mail") {
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
		return nil
	}

	return common.NewNewTypeError("could not be found")
}

// parseXARF parses an X-ARF report
func parseXARF(xarfReport email.EmailPart, xarfEvidence, subject string, fallbackDate *time.Time) ([]*events.Event, error) {
	event := events.NewEvent("xarf")

	// Get report body
	body, ok := xarfReport.Body.(string)
	if !ok {
		if bodyBytes, ok := xarfReport.Body.([]byte); ok {
			body = string(bodyBytes)
		} else {
			return nil, common.NewParserError("xarf report body is not a string")
		}
	}

	// Split by -- to get just the report part
	parts := strings.Split(body, "\n--")
	report := strings.TrimSpace(parts[0])

	// Clean User-Agent if present
	if strings.Contains(report, "User-Agent") {
		report = cleanUserAgent(report)
	}

	// Parse YAML
	var xarfReportMap map[string]interface{}
	err := yaml.Unmarshal([]byte(report), &xarfReportMap)
	if err != nil {
		// Check for specific blocklist.de error
		if strings.Contains(err.Error(), "Report-ID: @blocklist.de") {
			return nil, common.NewParserError("blocklist ran out of ids again")
		}
		return nil, common.NewParserError("could not load xarf data, yaml parsing error")
	}

	// Convert keys to lowercase
	xarfContent := make(map[string]interface{})
	for k, v := range xarfReportMap {
		xarfContent[strings.ToLower(k)] = v
	}

	// Add content recursively to headers
	addXARFContentRecursively(xarfContent, event, "")

	// Set IP from source
	if source, ok := xarfContent["source"].(string); ok {
		event.IP = source
	}

	// Add URL if source-type is uri
	addURL(event, xarfContent)

	// Add reporter organization if reported-from is present
	if reportedFrom, ok := xarfContent["reported-from"].(string); ok {
		if reportedFrom != "" {
			event.AddEventDetail(&events.Organisation{
				Name:         "reporter",
				ContactEmail: reportedFrom,
			})
		}
	}

	// Handle port info (not in xarf schema but some reporters include it)
	portKeys := []string{"source-port", "port", "ports"}
	for _, key := range portKeys {
		if portVal, ok := xarfContent[key]; ok {
			if portStr, ok := portVal.(string); ok {
				// Take first port if multiple
				ports := strings.Split(portStr, ", ")
				if len(ports) > 0 {
					if port, err := common.ParsePort(ports[0]); err == nil {
						event.Port = port
					}
				}
				break
			}
		}
	}

	// Add target if destination is present
	if destination, ok := xarfContent["destination"].(string); ok {
		if destination != "" {
			event.AddEventDetail(&events.Target{IP: destination})
		}
	}

	// Parse event type
	category := ""
	if cat, ok := xarfContent["category"].(string); ok {
		category = cat
	}

	typeString := ""
	if typ, ok := xarfContent["report-type"].(string); ok {
		typeString = strings.ToLower(typ)
	}

	if typeString != "" {
		switch typeString {
		case "login-attack":
			event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
		case "harvesting":
			event.EventTypes = []events.EventType{events.NewWebCrawler()}
		case "spam":
			event.EventTypes = []events.EventType{events.NewSpam()}
			event.RemoveRequirement("identification")
		case "phishing":
			event.EventTypes = []events.EventType{events.NewPhishing()}
		case "port-probe":
			event.EventTypes = []events.EventType{events.NewPortScan()}
		case "hack-attack":
			event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
		case "cryptocurrency-scam":
			event.EventTypes = []events.EventType{events.NewFraud()}
		case "fake-shop":
			event.EventTypes = []events.EventType{events.NewFraud()}
		default:
			// Check for malware in type string
			if strings.Contains(typeString, "malware") {
				malwareName := ""
				// Try to get malware name from antivirus-result or malware field
				for _, key := range []string{"antivirus-result", "malware"} {
					if val, ok := xarfContent[key].(string); ok {
						malwareName = val
						break
					}
				}
				event.EventTypes = []events.EventType{events.NewMalware(malwareName)}
			} else if strings.Contains(typeString, "bot") || typeString == "bot-infection" {
				botName := ""
				if bn, ok := xarfContent["bot-name"].(string); ok {
					botName = bn
				}
				event.EventTypes = []events.EventType{events.NewBot(botName)}
			} else if strings.Contains(typeString, "dnsbl") {
				event.EventTypes = []events.EventType{events.NewDNSBlocklist()}
			} else if strings.Contains(typeString, "denial") || strings.Contains(typeString, "ddos") {
				event.EventTypes = []events.EventType{events.NewDDoS()}
			} else if strings.Contains(typeString, "info") {
				// Try to infer from attached details
				if err := tryToFindTypeByAttachedDetail(xarfEvidence, subject, event); err != nil {
					return nil, err
				}
			} else {
				// Check category
				if category == "fraud" {
					event.EventTypes = []events.EventType{events.NewFraud()}
				} else {
					return nil, common.NewNewTypeError(typeString)
				}
			}
		}
	} else if category == "fraud" {
		event.EventTypes = []events.EventType{events.NewFraud()}
	}

	// Set event date
	if dateStr, ok := xarfContent["date"].(string); ok {
		if parsedDate := email.ParseDate(dateStr); parsedDate != nil {
			event.EventDate = parsedDate
		} else {
			event.EventDate = fallbackDate
		}
	} else {
		event.EventDate = fallbackDate
	}

	return []*events.Event{event}, nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get From address
	fromAddr, _ := common.GetFrom(serializedEmail, false)

	// Ignore @p44.net emails
	if strings.Contains(fromAddr, "@p44.net") {
		return nil, common.NewIgnoreError("@p44.net emails are ignored")
	}

	// Check auto-submitted header
	if autoSubmitted, ok := serializedEmail.Headers["auto-submitted"]; ok && len(autoSubmitted) > 0 {
		if strings.ToLower(autoSubmitted[0]) != "auto-generated" {
			return nil, common.NewIgnoreError("auto-submitted header indicates not auto-generated")
		}
	}

	// Get subject
	subject, _ := common.GetSubject(serializedEmail, false)
	if strings.HasPrefix(strings.ToLower(subject), "re:") {
		return nil, common.NewRejectError("subject starts with 're:'")
	}

	// Get content type
	contentType := getContentType(serializedEmail)

	// Check for X-ARF version
	xarfVersion := getXARFVersion(serializedEmail, contentType)

	var events []*events.Event

	// Parse X-ARF v0.2:PLAIN or v0.1
	if xarfVersion == "v0.2:PLAIN" || xarfVersion == "v0.1" {
		var xarfReport *email.EmailPart

		// Find the report.txt part
		for i := range serializedEmail.Parts {
			if looksLikeXARF(serializedEmail.Parts[i]) {
				xarfReport = &serializedEmail.Parts[i]
				break
			}
		}

		// Fallback to parts[1]
		if xarfReport == nil && len(serializedEmail.Parts) > 1 {
			xarfReport = &serializedEmail.Parts[1]
		}

		if xarfReport == nil {
			return nil, common.NewParserError("X-ARF report could not be found")
		}

		// Get evidence from parts[2]
		xarfEvidence := ""
		if len(serializedEmail.Parts) > 2 {
			if body, ok := serializedEmail.Parts[2].Body.(string); ok {
				xarfEvidence = body
			} else if bodyBytes, ok := serializedEmail.Parts[2].Body.([]byte); ok {
				xarfEvidence = string(bodyBytes)
			}
		}

		// Check content type of report
		var reportCT string
		if ct, ok := xarfReport.Headers["content-type"]; ok && len(ct) > 0 {
			parts := strings.Split(ct[0], ";")
			reportCT = strings.TrimSpace(strings.ToLower(parts[0]))
		}

		if reportCT == "text/plain" {
			// Get fallback date from headers
			var fallbackDate *time.Time
			if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
				fallbackDate = email.ParseDate(dateHeader[0])
			}

			parsedEvents, err := parseXARF(*xarfReport, xarfEvidence, subject, fallbackDate)
			if err != nil {
				return nil, err
			}
			events = parsedEvents
		}
	}

	// Check for xarf.json attachment (alternative format)
	for i := range serializedEmail.Parts {
		part := &serializedEmail.Parts[i]
		if ct, ok := part.Headers["content-type"]; ok && len(ct) > 0 {
			ctLower := strings.ToLower(ct[0])
			ctLower = strings.ReplaceAll(ctLower, `"`, "")
			ctLower = strings.ReplaceAll(ctLower, `'`, "")

			if strings.Contains(ctLower, "application/json") && strings.Contains(ctLower, "name=xarf.json") {
				// Parse JSON
				var xarfPart map[string]interface{}
				bodyStr, ok := part.Body.(string)
				if !ok {
					if bodyBytes, ok := part.Body.([]byte); ok {
						bodyStr = string(bodyBytes)
					} else {
						return nil, common.NewParserError("xarf.json body is not a string")
					}
				}

				if err := json.Unmarshal([]byte(bodyStr), &xarfPart); err != nil {
					return nil, common.NewParserError(fmt.Sprintf("failed to parse xarf.json: %v", err))
				}

				// Convert using xarf2event (would need implementation)
				// For now, return error indicating this needs implementation
				return nil, common.NewParserError("xarf.json format not yet supported - needs xarf2event conversion")
			}
		}
	}

	// Handle netcraft.com special case
	if strings.Contains(fromAddr, "@netcraft.com") {
		for _, event := range events {
			if event.IP == "" {
				body, err := common.GetBody(serializedEmail, true)
				if err == nil && event.URL != "" {
					// Extract domain and try to find IP
					// This is a simplified version - would need proper domain extraction
					urlParts := strings.Split(event.URL, ".")
					if len(urlParts) > 1 {
						ipCandidate := urlParts[1]
						ip := common.FindStringWithoutMarkers(body, ipCandidate, "")
						if ip != "" {
							event.IP = ip
						}
					}
				}
			}
		}
	}

	if len(events) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return events, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 12
}
