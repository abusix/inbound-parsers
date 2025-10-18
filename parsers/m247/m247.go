package m247

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/parsers/hetzner"
	"github.com/abusix/inbound-parsers/parsers/sony"
	email "github.com/abusix/inbound-parsers/pkg/email"
)

// Regular expressions for log parsing
var (
	// BOTNET_LOG_MATCHER: Parses botnet log entries with time, attacker IP, target IP, and port
	botnetLogMatcher = regexp.MustCompile(
		`.+?=(?P<time>.+)\s+\(attacker's IP\)=(?P<attacker>[0-9]{1,3}\.[0-9]{1,3}\.` +
			`[0-9]{1,3}\.[0-9]{1,3})\s+.+=(?P<target>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})` +
			`.+=(?P<port>[0-9]{1,6})`,
	)

	// SIP_LOG_MATCHER: Parses SIP scan logs with date/time and source/target IPs and ports
	sipLogMatcher = regexp.MustCompile(
		`(?P<month>\d{1,2})/(?P<day>\d{1,2}) (?P<time>[\d:]+) IP (?P<src_ip>` +
			`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(?P<src_port>[\d\.]+) > (?P<tg_ip>` +
			`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(?P<tg_port>[\d\.]+).*`,
	)

	// IP extraction pattern for finding IPs in text
	ipPattern = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)

	// Complaint list pattern: [ticket ID] ... address: IP
	complaintPattern = regexp.MustCompile(`(?i)\[ticket.*\r?\n.*`)

	// DDoS table pattern: | IP | IP | port | timestamp |
	ddosPattern = regexp.MustCompile(
		`\|\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*` +
			`\|\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*` +
			`\|\s*(\d*)\s*` +
			`\|([^|]*)`,
	)
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

	// Extract the "real subject" from the body (between ---- markers)
	realSubject := common.FindStringWithoutMarkers(body, "----", "----")
	realSubject = strings.TrimSpace(realSubject)

	// Get header date for year extraction and fallback dates
	headerDate := email.ParseDate(serializedEmail.Headers["date"][0])

	var result []*events.Event

	// Route to appropriate parsing function based on content
	if strings.Contains(body, "Automatic abuse report from") {
		result = parseBotnet(serializedEmail, body)
	} else if strings.Contains(body, "IP addresses of suspected botnet computers listed inside") {
		result = parseBotnetLog(serializedEmail, body)
	} else if strings.Contains(body, "Netscan detected") {
		if realSubject == "" {
			return nil, fmt.Errorf("real subject not found for netscan")
		}
		// Call hetzner's parseNetscan function
		hetznerParser := hetzner.NewParser()
		hetznerEvents, err := hetznerParser.Parse(serializedEmail)
		if err != nil {
			return nil, err
		}
		// Update parser name to m247
		for _, event := range hetznerEvents {
			event.Parser = "m247"
		}
		return hetznerEvents, nil
	} else if strings.Contains(body, "Hostile IP Address Report") {
		// These reports are forwarded and don't contain the attachment anymore -> useless
		if len(serializedEmail.Parts) != 2 {
			return nil, fmt.Errorf("new attachment found, update the parser")
		}
		return []*events.Event{}, nil // Empty list, not an error
	} else if strings.Contains(body, "We have detected abuse from") || strings.Contains(strings.ToLower(realSubject), "accessing our accounts") {
		subject, _ := common.GetSubject(serializedEmail, false)
		result = parseLoginAttack(body, subject, headerDate)
	} else if strings.Contains(body, "IDS found suspicious activity from") {
		result = parseTcpdump(serializedEmail, body, headerDate)
	} else if strings.Contains(body, "actively scanning and/or attacking external sites on the Internet") {
		result = parseActiveScan(body)
	} else if strings.Contains(body, "is attacking my network") {
		result = parseSipScan(body, realSubject, serializedEmail)
	} else if strings.Contains(body, "Vulnerability scanner") {
		result = parseVulnerabilityScanner(serializedEmail, body)
	} else if strings.Contains(body, "Attached is an X-ARF report") {
		if !strings.Contains(body, "Attachment logfile.log blocked") {
			return nil, fmt.Errorf("log file was added, change the parser")
		}
		result = parseXarfWithoutXarf(serializedEmail, body, realSubject)
	} else if strings.Contains(realSubject, "Spam complaint from") {
		result = parseSpam(serializedEmail, body)
	} else if strings.Contains(realSubject, "Unauthorized Access Trial") {
		result = parseUnauthorizedAccess(body)
	} else if strings.Contains(realSubject, "blacklisted from the PlayStation Network") {
		// Call sony parser
		sonyParser := sony.NewParser()
		sonyEvents, err := sonyParser.Parse(serializedEmail)
		if err != nil {
			return nil, err
		}
		return sonyEvents, nil
	} else if strings.Contains(realSubject, "abuse report about ") {
		if strings.Contains(realSubject, "bruteforcelogin") {
			result = parseAboutBruteforcelogin(realSubject)
		} else {
			result = parseAbout(body, realSubject)
		}
	} else if strings.Contains(realSubject, "crack our server") {
		result = parseServerBruteforcelogin(body, serializedEmail, realSubject, headerDate)
	} else if strings.Contains(realSubject, "Hacking attempt") || strings.Contains(body, "authenticator failed") {
		result = parseHackingAttempt(body, serializedEmail, realSubject)
	} else if strings.Contains(strings.ToLower(realSubject), "compromised host") || strings.Contains(strings.ToLower(body), "compromised host") {
		result = parseCompromisedHost(body, serializedEmail, realSubject)
	} else if strings.Contains(strings.ToLower(realSubject), "notification of network abuse complaint") {
		result = parseComplaintList(body, serializedEmail)
	} else if strings.Contains(strings.ToLower(realSubject), "ddos from your ips") {
		result = parseDdos(body, serializedEmail)
	} else {
		// Try copyright parser as fallback
		event := events.NewEvent("m247")
		// For simplicity, we'll just parse basic copyright info from the body
		// In the full implementation, we would call basic_event_copyright_parser
		// For now, use the header date as event date
		event.EventDate = headerDate
		event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}
		result = []*events.Event{event}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no event created")
	}

	return result, nil
}

func parseBotnet(serializedEmail *email.SerializedEmail, body string) []*events.Event {
	event := events.NewEvent("m247")
	event.EventTypes = []events.EventType{events.NewBot("")}
	event.EventDate = email.ParseDate(serializedEmail.Headers["date"][0])

	event.IP = common.FindStringWithoutMarkers(body, "email abuse report about the IP address ", " generated")

	// Handle "Our IP is" section with octet replacement
	if strings.Contains(strings.ToLower(body), "our ip is") {
		octet := strings.TrimSpace(common.FindStringWithoutMarkers(body, "of that octet is", "."))
		targetIPTemplate := common.FindStringWithoutMarkers(body, "Our IP is", "")
		targetIPTemplate = strings.ReplaceAll(targetIPTemplate, "[", "")
		targetIPTemplate = strings.ReplaceAll(targetIPTemplate, "]", "")
		targetIP := strings.ReplaceAll(targetIPTemplate, "X", octet)
		event.AddEventDetail(&events.Target{IP: targetIP})
	}

	return []*events.Event{event}
}

func parseBotnetLog(serializedEmail *email.SerializedEmail, body string) []*events.Event {
	var result []*events.Event

	matches := botnetLogMatcher.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) < 5 {
			continue
		}

		event := events.NewEvent("m247")
		event.EventTypes = []events.EventType{events.NewBot("")}

		// Parse time: replace / with -, replace first : with space, remove last 4 chars
		timeStr := match[1]
		timeStr = strings.ReplaceAll(timeStr, "/", "-")
		// Replace first : with space
		colonIdx := strings.Index(timeStr, ":")
		if colonIdx != -1 {
			timeStr = timeStr[:colonIdx] + " " + timeStr[colonIdx+1:]
		}
		// Remove last 4 chars
		if len(timeStr) >= 4 {
			timeStr = timeStr[:len(timeStr)-4]
		}
		event.EventDate = email.ParseDate(timeStr)

		event.IP = match[2] // attacker
		targetIP := match[3]
		targetPort := match[4]

		event.AddEventDetail(&events.Target{
			IP:   targetIP,
			Port: targetPort,
		})

		result = append(result, event)
	}

	return result
}

func parseTcpdump(serializedEmail *email.SerializedEmail, body string, headerDate *time.Time) []*events.Event {
	var result []*events.Event

	// Find the tcpdump section between markers
	starter := strings.Index(body, "--------- raw tcpdump output ----------")
	if starter == -1 {
		return nil
	}

	terminator := strings.Index(body[starter+1:], "--------- raw tcpdump output ----------")
	if terminator == -1 {
		// No second marker, use the rest
		terminator = len(body) - starter
	} else {
		terminator = starter + 1 + terminator
	}

	dump := body[starter:terminator]

	// Extract year from header date
	year := ""
	if headerDate != nil {
		year = strconv.Itoa(headerDate.Year())
	}

	matches := sipLogMatcher.FindAllStringSubmatch(dump, -1)
	for _, match := range matches {
		if len(match) < 8 {
			continue
		}

		event := events.NewEvent("m247")
		event.EventTypes = []events.EventType{events.NewPortScan()}

		month := match[1]
		day := match[2]
		timeStr := match[3]
		srcIP := match[4]
		srcPort := match[5]
		tgIP := match[6]
		tgPort := match[7]

		event.IP = srcIP
		if port, err := strconv.Atoi(srcPort); err == nil {
			event.Port = port
		}

		event.AddEventDetail(&events.Target{
			IP:   tgIP,
			Port: tgPort,
		})

		// Format: DD/MM/YYYY HH:MM:SS MET
		dateStr := fmt.Sprintf("%s/%s/%s %s MET", day, month, year, timeStr)
		event.EventDate = email.ParseDate(dateStr)

		result = append(result, event)
	}

	return result
}

func parseActiveScan(body string) []*events.Event {
	event := events.NewEvent("m247")
	event.EventTypes = []events.EventType{events.NewPortScan()}

	var date, timeStr, zone string
	ipMarker := false

	// Parse key:value pairs from body
	for _, line := range strings.Split(body, "\n") {
		if !strings.Contains(line, ":") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch key {
		case "date":
			// Parse MM/DD/YYYY to DD-MM-YYYY
			dateParts := strings.Split(value, "/")
			if len(dateParts) == 3 {
				date = fmt.Sprintf("%s-%s-%s", dateParts[1], dateParts[0], dateParts[2])
			}
		case "time":
			timeStr = value
		case "zone":
			if strings.Contains(value, "Chicago") {
				zone = "-06:00"
			} else {
				return nil // Unknown timezone
			}
		case "log":
			// Parse: source:port > target:port
			parts := strings.Split(value, " > ")
			if len(parts) == 2 {
				source := parts[0]
				sourceParts := strings.Split(source, ":")
				if len(sourceParts) >= 2 {
					event.IP = strings.Join(sourceParts[:len(sourceParts)-1], ":")
					if port, err := strconv.Atoi(sourceParts[len(sourceParts)-1]); err == nil {
						event.Port = port
					}
				}

				targetParts := strings.Split(parts[1], ":")
				if len(targetParts) >= 2 {
					targetIP := strings.Join(targetParts[:len(targetParts)-1], ":")
					targetPort := targetParts[len(targetParts)-1]
					event.AddEventDetail(&events.Target{
						IP:   targetIP,
						Port: targetPort,
					})
					ipMarker = true
				}
			}
		}
	}

	if date == "" || timeStr == "" || zone == "" {
		return nil
	}

	dateStr := fmt.Sprintf("%s %s %s", date, timeStr, zone)
	event.EventDate = email.ParseDate(dateStr)

	if !ipMarker {
		return nil
	}

	return []*events.Event{event}
}

func parseSipScan(body, realSubject string, serializedEmail *email.SerializedEmail) []*events.Event {
	event := events.NewEvent("m247")
	event.EventTypes = []events.EventType{events.NewPortScan()}
	event.IP = realSubject

	port := common.FindStringWithoutMarkers(body, "connect to port ", " ")
	if portNum, err := strconv.Atoi(port); err == nil {
		event.Port = portNum
	}

	event.EventDate = email.ParseDate(serializedEmail.Headers["date"][0])

	return []*events.Event{event}
}

func parseVulnerabilityScanner(serializedEmail *email.SerializedEmail, body string) []*events.Event {
	event := events.NewEvent("m247")
	event.EventTypes = []events.EventType{events.NewPortScan()}
	event.EventDate = email.ParseDate(serializedEmail.Headers["date"][0])

	event.IP = common.FindStringWithoutMarkers(body, "IP/cidr: ", "")

	sblRef := common.FindStringWithoutMarkers(strings.ToLower(body), "sbl ref: ", "")
	if sblRef != "" {
		event.EventTypes = append(event.EventTypes, events.NewBlacklist(strings.ToUpper(sblRef)))
	}

	return []*events.Event{event}
}

func parseXarfWithoutXarf(serializedEmail *email.SerializedEmail, body, subject string) []*events.Event {
	event := events.NewEvent("m247")

	// Subject format: IP - DATE
	parts := strings.SplitN(subject, "- ", 2)
	if len(parts) == 2 {
		event.IP = strings.TrimSpace(parts[0])
		event.EventDate = email.ParseDate(parts[1])
	}

	reasonBlock := common.FindStringWithoutMarkers(body, "The IP address", "Attached is an X-ARF report")

	if strings.Contains(reasonBlock, "attacking firewall") {
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	} else {
		return nil // Unknown reason
	}

	return []*events.Event{event}
}

func parseSpam(serializedEmail *email.SerializedEmail, body string) []*events.Event {
	event := events.NewEvent("m247")
	event.EventDate = email.ParseDate(serializedEmail.Headers["date"][0])
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Normalize line endings
	body = strings.ReplaceAll(body, "\r\n", "\n")

	event.IP = common.FindStringWithoutMarkers(body, "Source-IP", "")
	replyTo := common.FindStringWithoutMarkers(body, "Reply-To: ", "")
	from := common.FindStringWithoutMarkers(body, "From: ", "")

	// Add headers to event
	if event.Headers == nil {
		event.Headers = make(map[string]interface{})
	}

	ignoreHeaders := map[string]bool{"date": true}
	if replyTo != "" {
		event.Headers["reply-to"] = []string{replyTo}
		ignoreHeaders["reply-to"] = true
	}
	if from != "" {
		event.Headers["from"] = []string{from}
		ignoreHeaders["from"] = true
	}

	// Copy other headers from serialized email
	for key, values := range serializedEmail.Headers {
		if !ignoreHeaders[key] {
			event.Headers[key] = values
		}
	}

	return []*events.Event{event}
}

func parseUnauthorizedAccess(body string) []*events.Event {
	event := events.NewEvent("m247")
	loginAttack := events.NewLoginAttack("", "")
	event.EventTypes = []events.EventType{loginAttack}

	// Find the data section between ---------------
	lineBreak := "\n"
	if strings.Contains(body, "\r\n") {
		lineBreak = "\r\n"
	}

	dataPart := common.FindStringWithoutMarkers(body, "---------------"+lineBreak, "---------------")
	if dataPart == "" {
		return nil
	}

	for _, line := range strings.Split(dataPart, lineBreak) {
		if !strings.Contains(line, ":") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if strings.Contains(key, "Date") {
			// Extract timezone from key
			timezone := common.FindStringWithoutMarkers(key, "(GMT", ")")
			if len(timezone) == 2 {
				timezone = string(timezone[0]) + "0" + string(timezone[1])
			}
			// Value format: YYYY-MM-DD HH:MM:SS~HH:MM:SS
			datePart := strings.Split(value, "~")[0]
			dateStr := datePart + timezone
			event.EventDate = email.ParseDate(dateStr)
		} else if strings.Contains(key, "Source IP") {
			event.IP = value
		} else if strings.Contains(key, "Destination IP") {
			event.AddEventDetail(&events.Target{IP: value})
		}
	}

	return []*events.Event{event}
}

func parseAbout(body, realSubject string) []*events.Event {
	event := events.NewEvent("m247")
	event.IP = common.FindStringWithoutMarkers(realSubject, "about ", " ")

	// Get block around "Hostname or IP"
	block := common.GetBlockAround(body, "Hostname or IP")
	for _, line := range block {
		if !strings.Contains(line, ":") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.Trim(parts[1], "/\"'. \t\n\r")

		if strings.Contains(key, "time") {
			event.EventDate = email.ParseDate(value)
		} else if strings.Contains(key, "service") {
			if value == "portscan" {
				event.EventTypes = []events.EventType{events.NewPortScan()}
			} else {
				// Map service name to event type
				// For simplicity, using unknown for unmapped types
				event.EventTypes = []events.EventType{events.NewUnknown()}
			}
		} else if strings.Contains(key, "ip") || strings.Contains(key, "hostname") {
			// Try to set as IP, fallback to URL
			if common.IsURL(value) {
				event.URL = value
			} else {
				event.IP = value
			}
		}
	}

	return []*events.Event{event}
}

func parseAboutBruteforcelogin(realSubject string) []*events.Event {
	event := events.NewEvent("m247")
	event.IP = common.FindStringWithoutMarkers(realSubject, "about ", " ")

	// Subject format: ... about IP - DATE - ...
	fields := strings.Split(realSubject, "-")
	if len(fields) > 1 {
		event.EventDate = email.ParseDate(fields[1])
	}

	event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

	return []*events.Event{event}
}

func parseServerBruteforcelogin(body string, serializedEmail *email.SerializedEmail, realSubject string, headerDate *time.Time) []*events.Event {
	event := events.NewEvent("m247")
	event.IP = realSubject

	// Try to extract username from HTML part
	user := ""
	if len(serializedEmail.Parts) > 1 {
		partBody, _ := common.GetBody(serializedEmail, false)
		user = common.FindStringWithoutMarkers(partBody, "user=&lt;", "&")
	}

	event.EventTypes = []events.EventType{events.NewLoginAttack(user, "")}

	// Parse log section
	logLines := common.GetBlockAfterWithStop(body, "The log exerpts follow", "")
	if len(logLines) > 0 {
		log := strings.Join(logLines, " ")

		target := strings.TrimSpace(common.FindStringWithoutMarkers(log, "On", ":"))
		targetParts := strings.Fields(target)
		if len(targetParts) >= 2 {
			targetURL := targetParts[0]
			targetIP := strings.Trim(targetParts[1], "()")
			event.AddEventDetail(&events.Target{
				IP:  targetIP,
				URL: targetURL,
			})
		}

		// Parse date
		year := ""
		if headerDate != nil {
			year = strconv.Itoa(headerDate.Year())
		}

		timezone := common.FindStringWithoutMarkers(body, "Times are ", " ")
		if timezone != "" && len(log) > 0 {
			logParts := strings.SplitN(log, ":", 2)
			if len(logParts) > 1 {
				timeParts := strings.Fields(strings.TrimSpace(logParts[1]))
				if len(timeParts) >= 3 {
					dateStr := fmt.Sprintf("%s %s %s %s %s", year, timeParts[0], timeParts[1], timeParts[2], timezone)
					event.EventDate = email.ParseDate(dateStr)
				}
			}
		}
	}

	return []*events.Event{event}
}

func parseLoginAttack(body, subject string, headerDate *time.Time) []*events.Event {
	event := events.NewEvent("m247")

	ip := strings.TrimSpace(common.FindStringWithoutMarkers(body, "IP address (", ")"))
	if ip == "" {
		ip = common.FindStringWithoutMarkers(body, "Abuse from", "")
	}
	event.IP = ip

	targetIP := strings.TrimSpace(common.FindStringWithoutMarkers(body, "lip=", ","))
	event.AddEventDetail(&events.Target{IP: targetIP})

	event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

	externalID := strings.TrimSpace(common.FindStringWithoutMarkers(subject, "ID:", "]"))
	if externalID != "" {
		event.AddEventDetail(&events.ExternalID{ID: externalID})
	}

	tz := common.FindStringWithoutMarkers(body, "Local timezone is ", " ")
	dateLine := common.GetNonEmptyLineAfter(body, "Local timezone is ")
	dateFields := strings.Fields(dateLine)

	year := ""
	if headerDate != nil {
		year = strconv.Itoa(headerDate.Year())
	}

	if len(dateFields) >= 3 {
		if strings.Contains(dateFields[0], year) {
			dateStr := fmt.Sprintf("%s %s%s", dateFields[0], dateFields[1], tz)
			event.EventDate = email.ParseDate(dateStr)
		} else {
			dateStr := fmt.Sprintf("%s-%s-%s %s %s", dateFields[1], dateFields[0], year, dateFields[2], tz)
			event.EventDate = email.ParseDate(dateStr)
		}
	} else {
		event.EventDate = headerDate
	}

	return []*events.Event{event}
}

func parseHackingAttempt(body string, serializedEmail *email.SerializedEmail, realSubject string) []*events.Event {
	event := events.NewEvent("m247")
	event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	event.IP = realSubject
	event.EventDate = email.ParseDate(serializedEmail.Headers["date"][0])

	// Extract target IPs
	targetText := common.FindStringWithoutMarkers(body, "Our service being attacked:", "")
	if targetText == "" {
		targetText = common.FindStringWithoutMarkers(body, "Our server", "")
	}

	targetIPSet := make(map[string]bool)
	if targetText != "" {
		matches := ipPattern.FindAllString(targetText, -1)
		for _, ip := range matches {
			targetIPSet[ip] = true
		}
	}

	// Add unique target IPs
	for ip := range targetIPSet {
		event.AddEventDetail(&events.Target{IP: ip})
	}

	return []*events.Event{event}
}

func parseCompromisedHost(body string, serializedEmail *email.SerializedEmail, realSubject string) []*events.Event {
	event := events.NewEvent("m247")
	event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	event.IP = realSubject
	event.EventDate = email.ParseDate(serializedEmail.Headers["date"][0])

	return []*events.Event{event}
}

func parseComplaintList(body string, serializedEmail *email.SerializedEmail) []*events.Event {
	var result []*events.Event

	matches := complaintPattern.FindAllString(strings.ToLower(body), -1)
	for _, entry := range matches {
		var eventType events.EventType
		if strings.Contains(entry, "copyright") {
			eventType = events.NewCopyright("", "", "")
		} else {
			continue // Skip unknown types
		}

		externalID := common.FindStringWithoutMarkers(entry, "ticket ", "]")
		ip := common.FindStringWithoutMarkers(entry, "address: ", "\r")
		if ip == "" {
			ip = common.FindStringWithoutMarkers(entry, "address: ", "\n")
		}

		event := events.NewEvent("m247")
		event.EventDate = email.ParseDate(serializedEmail.Headers["date"][0])
		event.EventTypes = []events.EventType{eventType}
		event.IP = ip

		if externalID != "" {
			event.AddEventDetail(&events.ExternalID{ID: externalID})
		}

		result = append(result, event)
	}

	return result
}

func parseDdos(body string, serializedEmail *email.SerializedEmail) []*events.Event {
	var result []*events.Event

	matches := ddosPattern.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) < 5 {
			continue
		}

		event := events.NewEvent("m247")
		event.IP = match[1]
		event.AddEventDetail(&events.Target{
			IP:   match[2],
			Port: match[3],
		})
		event.EventDate = email.ParseDate(match[4])
		event.EventTypes = []events.EventType{events.NewDDoS()}

		result = append(result, event)
	}

	return result
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
