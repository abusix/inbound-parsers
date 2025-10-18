package telecomitalia

import (
	"regexp"
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

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)
	bodyLower := strings.ToLower(body)

	// Extract IP from subject if present
	ip := isIP(extractOneIP(subjectLower))

	// Get event date from headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	// Create base event
	event := events.NewEvent("telecomitalia")
	event.EventDate = eventDate
	event.IP = ip

	// Route to appropriate parser based on body content
	if strings.Contains(bodyLower, "phishing server") {
		return parseCompromisedServer(body, bodyLower, eventDate, event)
	} else if strings.Contains(bodyLower, "block the following") {
		return parsePhishing(body, bodyLower, event)
	} else if strings.Contains(bodyLower, "suspicious activity") && strings.Contains(bodyLower, "brute force") {
		return parseLoginAttack(body)
	} else if strings.Contains(bodyLower, "suspicious activity") && strings.Contains(bodyLower, "sql injection") {
		return parseExploit(body)
	} else if strings.Contains(bodyLower, "suspicious activity") && strings.Contains(bodyLower, "wordpress attack") {
		return parseExploitWordpress(body)
	} else if strings.Contains(bodyLower, "suspicious activity") &&
		(strings.Contains(bodyLower, "unauthorized access") || strings.Contains(bodyLower, "security probing")) {
		return parseUnauthorizedAccess(serializedEmail)
	} else if strings.Contains(subjectLower, "malicious code hosted") {
		event.EventTypes = []events.EventType{events.NewFraud()}
		event.URL = common.FindStringWithoutMarkers(bodyLower, "url:", "")
		return []*events.Event{event}, nil
	} else if strings.Contains(bodyLower, "stolen valid credentials") {
		event.EventTypes = []events.EventType{events.NewSpam()}
		return []*events.Event{event}, nil
	} else if strings.Contains(bodyLower, "phishing") || strings.Contains(subjectLower, "phishing") {
		// Extract IP from Received headers if not present
		if event.IP == "" && strings.Contains(body, "Received: from") {
			var allIPs []string
			for _, line := range strings.Split(body, "\n") {
				if strings.HasPrefix(line, "Received:") {
					if extractedIP := extractOneIP(line); extractedIP != "" {
						allIPs = append(allIPs, extractedIP)
					}
				}
			}
			if len(allIPs) > 0 {
				event.IP = allIPs[len(allIPs)-1]
			}
		}
		event.EventTypes = []events.EventType{events.NewPhishing()}
		return []*events.Event{event}, nil
	} else if strings.Contains(subjectLower, "brand misuse") {
		event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}

		if event.IP == "" {
			if matchIP := common.FindStringWithoutMarkers(bodyLower, "ip address:", ""); matchIP != "" {
				event.IP = matchIP
			}
		}

		if matchURL := common.FindStringWithoutMarkers(bodyLower, "url:", ""); matchURL != "" {
			event.URL = matchURL
		}

		return []*events.Event{event}, nil
	}

	return nil, common.NewParserError("not found")
}

// parseCompromisedServer handles phishing server reports
func parseCompromisedServer(body, bodyLower string, date *time.Time, event *events.Event) ([]*events.Event, error) {
	accountEmail := ""

	// Extract date
	if strings.Contains(bodyLower, "date:") {
		if d := common.FindStringWithoutMarkers(bodyLower, "date:", ""); d != "" {
			date = email.ParseDate(d)
		}
	} else if strings.Contains(bodyLower, "date-time:") {
		if d := common.FindStringWithoutMarkers(bodyLower, "date-time:", ""); d != "" {
			date = email.ParseDate(d)
		}
	}

	// Extract account email
	if accountStr := common.FindStringWithoutMarkers(bodyLower, "account email:", ""); accountStr != "" {
		accountEmail = strings.ReplaceAll(strings.TrimSpace(accountStr), "*", "")
	}

	// Extract IP if not present
	if event.IP == "" {
		if matchIP := common.FindStringWithoutMarkers(bodyLower, "ip address:", ""); matchIP != "" {
			event.IP = matchIP
		}
	}

	event.EventDate = date
	event.EventTypes = []events.EventType{events.NewCompromisedAccount(accountEmail)}

	return []*events.Event{event}, nil
}

// parsePhishing handles phishing URL blocking requests
func parsePhishing(body, bodyLower string, event *events.Event) ([]*events.Event, error) {
	// Remove HTML tags from block
	blockLines := getBlockAfter(strings.ReplaceAll(body, "*", ""), "block the following")
	blockText := strings.Join(blockLines, " ")

	// Remove HTML tags
	tagPattern := regexp.MustCompile(`<.*?>`)
	url := tagPattern.ReplaceAllString(blockText, "")
	url = strings.TrimSpace(strings.ToLower(url))

	// Clean up URL
	url = strings.ReplaceAll(url, "url:", "")
	url = strings.TrimSpace(url)
	url = strings.ReplaceAll(url, "hxxp", "http")

	// Split on IP: if present
	if idx := strings.Index(url, "ip:"); idx != -1 {
		url = url[:idx]
	}
	url = strings.TrimSpace(url)

	event.URL = url
	event.EventTypes = []events.EventType{events.NewPhishing()}

	return []*events.Event{event}, nil
}

// parseLoginAttack handles brute force login attacks
func parseLoginAttack(body string) ([]*events.Event, error) {
	logs := cleanLog(body, "Event Count Destination IP Source IP First Time", "")

	var eventsList []*events.Event
	for _, log := range logs {
		parts := strings.Split(log, "\t")
		if len(parts) < 4 {
			continue
		}

		// Parse: Event Count, Dst IP, Src IP, Date
		dstIP := parts[1]
		srcIP := parts[2]
		date := email.ParseDate(parts[3])

		event := events.NewEvent("telecomitalia")
		event.IP = srcIP
		if !strings.Contains(strings.ToLower(dstIP), ".xx") {
			event.AddEventDetail(&events.Target{IP: dstIP})
		}
		event.EventDate = date
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

// parseExploit handles SQL injection attacks
func parseExploit(body string) ([]*events.Event, error) {
	logs := cleanLog(body, "Time Src IP Src Port Dest IP Dest Port", "")

	var eventsList []*events.Event
	for _, log := range logs {
		// Split on multiple spaces
		fields := regexp.MustCompile(`\s\s+`).Split(log, -1)
		if len(fields) < 4 {
			continue
		}

		date := fields[0]
		inc := 0

		// Check if time is in next field
		if len(fields) > 1 && !strings.Contains(fields[1], ".") {
			date += " " + fields[1]
			inc = 1
		}

		srcIP := fields[1+inc]
		var srcPort string
		if len(fields) > 2+inc && !strings.Contains(fields[2+inc], "n/a") {
			srcPort = fields[2+inc]
		}

		var officialURL, dstPort string
		if len(fields) > 3+inc {
			if strings.Contains(fields[3+inc], " ") {
				parts := strings.SplitN(fields[3+inc], " ", 2)
				officialURL = parts[0]
				dstPort = parts[1]
			} else {
				dstPort = fields[3+inc]
			}
		}

		if strings.Contains(dstPort, "n/a") {
			dstPort = ""
		}

		event := events.NewEvent("telecomitalia")
		event.IP = srcIP
		if srcPort != "" {
			if port, err := common.ParsePort(srcPort); err == nil {
				event.Port = port
			}
		}
		event.AddEventDetail(&events.Target{Port: dstPort, URL: officialURL})
		event.EventDate = email.ParseDate(date)
		event.EventTypes = []events.EventType{events.NewExploit()}
		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

// parseExploitWordpress handles WordPress attacks
func parseExploitWordpress(body string) ([]*events.Event, error) {
	header := "time_received_tz_isoformat\tremote_host\trequest_first_line\trequest_method\tstatus"
	headerSpaced := strings.Join(strings.Fields(header), " ")

	var logs []string
	if strings.Contains(strings.ToLower(body), "events:") &&
		strings.Contains(body, "time_received_tz_isoformat") {
		// Replace events: with events:\n\n to separate it
		bodyModified := strings.Replace(body, "events:", "events:\n\n", 1)
		logs = cleanLog(bodyModified, headerSpaced, "events:")
	} else {
		logs = cleanLog(body, headerSpaced, "")
	}

	var eventsList []*events.Event
	for _, log := range logs {
		values := strings.Split(log, "\t")
		if len(values) < 3 {
			continue
		}

		event := events.NewEvent("telecomitalia")
		event.EventDate = email.ParseDate(strings.ReplaceAll(values[0], "@", ""))
		event.IP = values[1]
		event.AddEventDetail(&events.HttpRequest{Method: values[2]})
		event.EventTypes = []events.EventType{events.NewExploit()}
		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

// parseUnauthorizedAccess handles unauthorized access reports
func parseUnauthorizedAccess(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, _ := common.GetSubject(serializedEmail, true)

	event := events.NewEvent("telecomitalia")

	// Get date from headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	event.IP = subject
	event.EventTypes = []events.EventType{events.NewExploit()}

	return []*events.Event{event}, nil
}

// cleanLog extracts log lines from body text
func cleanLog(body, header, startsWith string) []string {
	if startsWith == "" {
		startsWith = "Below follows a listing"
	}

	logs := getBlockAfter(body, startsWith)

	// Remove lines starting with '.'
	var filtered []string
	for _, log := range logs {
		if !strings.HasPrefix(log, ".") {
			filtered = append(filtered, log)
		}
	}
	logs = filtered

	// Remove header if present
	if len(logs) > 0 {
		firstLineSpaced := strings.Join(strings.Fields(logs[0]), " ")
		if firstLineSpaced == header {
			logs = logs[1:]
		}
	}

	return logs
}

// getBlockAfter returns lines after a marker until an empty line
func getBlockAfter(text, startMarker string) []string {
	idx := strings.Index(text, startMarker)
	if idx == -1 {
		return nil
	}

	// Skip to the next line after the marker
	remaining := text[idx+len(startMarker):]
	newlineIdx := strings.Index(remaining, "\n")
	if newlineIdx != -1 {
		remaining = remaining[newlineIdx+1:]
	}

	lines := strings.Split(remaining, "\n")
	var result []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			break
		}
		result = append(result, line)
	}

	return result
}

// extractOneIP extracts the first IP address from a string
func extractOneIP(text string) string {
	// Try IPv4 first
	ipv4Pattern := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	if match := ipv4Pattern.FindString(text); match != "" {
		return match
	}

	// Try IPv6
	ipv6Pattern := regexp.MustCompile(`\b[0-9a-fA-F:]+:[0-9a-fA-F:]+\b`)
	if match := ipv6Pattern.FindString(text); match != "" {
		return match
	}

	return ""
}

// isIP checks if a string is a valid IP address
func isIP(ip string) string {
	if ip == "" {
		return ""
	}

	// Basic validation - check for IPv4
	ipv4Pattern := regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	if ipv4Pattern.MatchString(ip) {
		return ip
	}

	// Check for IPv6
	ipv6Pattern := regexp.MustCompile(`^[0-9a-fA-F:]+$`)
	if ipv6Pattern.MatchString(ip) && strings.Contains(ip, ":") {
		return ip
	}

	return ""
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
