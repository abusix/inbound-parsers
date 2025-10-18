package cert_in

import (
	"encoding/csv"
	"fmt"
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
	bodyLower := strings.ToLower(body)

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	event := events.NewEvent("cert_in")

	// Extract date from headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	// Extract external reference ID from subject
	refPattern := regexp.MustCompile(`(?i)ref:\s+(\S+)`)
	if matches := refPattern.FindStringSubmatch(subject); len(matches) > 1 {
		event.AddEventDetail(&events.ExternalID{ID: matches[1]})
	}

	// Route to appropriate sub-parser based on subject/body content
	if strings.Contains(subjectLower, "phishing") {
		return parsePhishing(body, subjectLower, event)
	} else if strings.Contains(subjectLower, "botnet") {
		return parseBotnet(serializedEmail, body, event)
	} else if containsAny(subjectLower, []string{"malware", "c2 server", "ransomware"}) ||
		containsAny(bodyLower, []string{"malware", "mentioned campaign"}) {
		return parseMalware(serializedEmail, body, event)
	} else if strings.Contains(subjectLower, "spamming") {
		return parseSpam(body, subject, event)
	} else if containsAny(subjectLower, []string{"brute force", "bruteforce"}) {
		return parseBruteForce(serializedEmail, body, subjectLower, event)
	} else if containsAny(subjectLower, []string{"scanning activity", "scanning activities"}) {
		return parsePortscan(serializedEmail, body, subject, event)
	} else if containsAny(subjectLower, []string{
		"compromised device", "compromise of device",
		"vulnerable exposed dicom storage server", "potentially vulnerable",
		"server instances under your control"}) {
		return parseCompromisedServer(serializedEmail, body, event)
	} else if strings.Contains(subjectLower, "ddos attack") {
		return parseDDoS(body, subject, event)
	} else if strings.Contains(subjectLower, "possible security misconfiguration vulnerability") {
		return parseOpen(body, event)
	} else if containsAny(subjectLower, []string{
		"malicious apk file hosted", "intrusion attempt", "unauthorised activity",
		"malicious activities", "unauthorized activity", "unauthorized  activity",
		"unauthorized malicious activity"}) {
		return parseMaliciousActivity(serializedEmail, body, subject, event)
	} else if strings.Contains(subjectLower, "defacement") {
		return parseDefacement(body, subject, event)
	}

	return nil, common.NewNewTypeError(subject)
}

// Helper functions

func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

func getEntryForKeys(entry map[string]string, keys []string) string {
	for _, key := range keys {
		if value, ok := entry[key]; ok && value != "" {
			return value
		}
	}
	return ""
}

func parseCSVFromString(csvData string) ([]map[string]string, error) {
	reader := csv.NewReader(strings.NewReader(csvData))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no CSV data")
	}

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

func parseDate(dateStr string, formats []string) (*time.Time, error) {
	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return &t, nil
		}
	}
	return nil, fmt.Errorf("unable to parse date: %s", dateStr)
}

func copyEvent(e *events.Event) *events.Event {
	newEvent := events.NewEvent(e.Parser)
	newEvent.IP = e.IP
	newEvent.URL = e.URL
	newEvent.Port = e.Port
	newEvent.Domain = e.Domain
	newEvent.EventDate = e.EventDate
	newEvent.EventDetails = append([]events.EventDetail{}, e.EventDetails...)
	return newEvent
}

// Sub-parsers

func parseMalware(serializedEmail *email.SerializedEmail, body string, eventTemplate *events.Event) ([]*events.Event, error) {
	var result []*events.Event
	eventTemplate.EventTypes = []events.EventType{events.NewMalware("")}

	// Try CSV attachment first
	if rawCSV, err := common.FindFirstAttachmentWithMimeType(serializedEmail, ".csv"); err == nil {
		entries, err := parseCSVFromString(rawCSV)
		if err == nil {
			ips := make(map[string]bool)
			for _, entry := range entries {
				ip := getEntryForKeys(entry, []string{"Source IP", "Source Ip", "C2 IP"})
				if ip != "" && !ips[ip] {
					ips[ip] = true
					event := copyEvent(eventTemplate)
					event.IP = ip

					// Parse date
					dateStr := getEntryForKeys(entry, []string{"Timestamp", "Time"})
					if dateStr != "" {
						dateStr = strings.TrimSpace(dateStr)
						if t, err := parseDate(dateStr, []string{
							"2006-01-02 15:04:05",
							"02-01-2006 15:04:05",
						}); err == nil {
							event.EventDate = t
						}
					}

					// Port
					if portStr := getEntryForKeys(entry, []string{"Source Port", "C2 Port"}); portStr != "" {
						if port, err := common.ParsePort(portStr); err == nil {
							event.Port = port
						}
					}

					// Target
					dstIP := entry["Destination Ip"]
					dstPort := entry["Destination Port"]
					if dstIP != "" || dstPort != "" {
						event.AddEventDetail(&events.Target{IP: dstIP, Port: dstPort})
					}

					// ASN
					asn := getEntryForKeys(entry, []string{"Src ASN", "Source ASN"})
					asnNumber := entry["ASN Number"]
					if asn != "" || asnNumber != "" {
						event.AddEventDetail(&events.ASN{ASN: asnNumber, ASName: asn})
					}

					result = append(result, event)
				}
			}
			return result, nil
		}
	}

	// Try IP extraction from body
	body = strings.ReplaceAll(body, " : ", ":")
	if ip := common.FindStringWithoutMarkers(body, "IP:\"", "\""); ip != "" {
		eventTemplate.IP = ip
		eventTemplate.URL = common.GetNonEmptyLineAfter(body, "The following URL is hosting malware:")
		return []*events.Event{eventTemplate}, nil
	}

	// Try URL block extraction
	if strings.Contains(body, "The URL hosting malware :") {
		urlBlock := common.GetBlockAfterWithStop(body, "The URL hosting malware :", "")
		for _, url := range urlBlock {
			event := copyEvent(eventTemplate)
			event.URL = url
			result = append(result, event)
		}
		if len(result) > 0 {
			return result, nil
		}
	}

	// Try IP and port regex
	if strings.Contains(body, "IP and port") {
		pattern := regexp.MustCompile(`(?i)ip and port:\s*(\S+):(\d+)\s+last seen:\s*(\S+\s+\S+)`)
		matches := pattern.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) >= 4 {
				event := copyEvent(eventTemplate)
				event.IP = strings.ReplaceAll(match[1], "[.]", ".")
				if port, err := common.ParsePort(match[2]); err == nil {
					event.Port = port
				}
				dateStr := strings.TrimSpace(match[3]) + ":00"
				if t, err := parseDate(dateStr, []string{"02-01-2006 15:04:05"}); err == nil {
					event.EventDate = t
				}
				result = append(result, event)
			}
		}
		if len(result) > 0 {
			return result, nil
		}
	}

	// Try malware pattern
	pattern := regexp.MustCompile(`(?i)ip.*:\s*((\d|\[\.]))+:\s*(\d+)\s*((url:|urls:)\s+\S*\s*\S*\s*)*(\s*c2 server:.*\s+)*(\s*last seen:.*\s+)*malware:\s+(.*)`)
	matches := pattern.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) >= 9 {
			event := copyEvent(eventTemplate)
			event.EventTypes = []events.EventType{events.NewMalware(strings.TrimSpace(match[8]))}
			event.IP = strings.ReplaceAll(match[1], "[.]", ".")
			if port, err := common.ParsePort(match[3]); err == nil {
				event.Port = port
			}
			result = append(result, event)
		}
	}

	if len(result) == 0 {
		return []*events.Event{eventTemplate}, nil
	}
	return result, nil
}

func parsePhishing(body, subjectLower string, eventTemplate *events.Event) ([]*events.Event, error) {
	var result []*events.Event
	urls := make(map[string]bool)
	eventTemplate.EventTypes = []events.EventType{events.NewPhishing()}

	// Try to extract IP from subject
	if ip := common.FindStringWithoutMarkers(subjectLower, "ip", "ref"); ip != "" {
		eventTemplate.IP = ip
	}

	// Try different URL extraction methods
	body = strings.ReplaceAll(body, " :", ":")
	for _, tag := range []string{"The Phishing URL is:", "The Phishing URL is as follows:", "Phishing URL:"} {
		for _, endTag := range []string{"Please note", "Relevant screenshots"} {
			if url := common.FindStringWithoutMarkers(body, tag, endTag); url != "" {
				url = regexp.MustCompile(`\s`).ReplaceAllString(url, "")
				urls[url] = true
				break
			}
		}
	}

	if len(urls) == 0 && strings.Contains(body, "Phishing URLs are:") {
		body = strings.ReplaceAll(body, "are:", "are:\n")
		urlBlock := common.GetBlockAfterWithStop(body, "Phishing URLs are:", "")
		for _, url := range urlBlock {
			urls[url] = true
		}
	}

	if len(urls) == 0 {
		if url := common.GetNonEmptyLineAfter(body, "The Malicious URL is as follows:"); url != "" {
			urls[url] = true
		}
	}

	for url := range urls {
		event := copyEvent(eventTemplate)
		event.URL = url
		result = append(result, event)
	}

	if len(result) == 0 {
		return []*events.Event{eventTemplate}, nil
	}
	return result, nil
}

func parseSpam(body, subject string, eventTemplate *events.Event) ([]*events.Event, error) {
	var result []*events.Event
	eventTemplate.EventTypes = []events.EventType{events.NewSpam()}
	ips := make(map[string]bool)

	subjectLower := strings.ToLower(subject)
	if ip := common.FindStringWithoutMarkers(subjectLower, "ip", "ref"); ip != "" {
		eventTemplate.URL = common.FindStringWithoutMarkers(subject, "from Domain \"", "\"/")
		eventTemplate.IP = ip
		return []*events.Event{eventTemplate}, nil
	}

	pattern := regexp.MustCompile(`(?i)received:\s*from\s+\*\*\*\s+by\s+(\S+);`)
	matches := pattern.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) >= 2 {
			ip := match[1]
			if !ips[ip] {
				ips[ip] = true
				event := copyEvent(eventTemplate)
				event.IP = ip
				result = append(result, event)
			}
		}
	}

	if len(result) == 0 {
		return []*events.Event{eventTemplate}, nil
	}
	return result, nil
}

func parseMaliciousActivity(serializedEmail *email.SerializedEmail, body, subject string, eventTemplate *events.Event) ([]*events.Event, error) {
	var result []*events.Event
	eventTemplate.EventTypes = []events.EventType{events.NewMaliciousActivity()}

	// Try CSV attachments
	var entries []map[string]string
	if rawCSV, err := common.FindFirstAttachmentWithMimeType(serializedEmail, ".csv"); err == nil {
		entries, _ = parseCSVFromString(rawCSV)
	}

	if entries != nil && len(entries) > 0 {
		for _, entry := range entries {
			event := copyEvent(eventTemplate)

			// Parse date
			if dateStr := entry["Timestamp"]; dateStr != "" {
				parts := strings.Split(dateStr, ".")
				if len(parts) > 0 {
					if t, err := parseDate(parts[0], []string{"Jan 2, 2006 @ 15:04:05"}); err == nil {
						event.EventDate = t
					}
				}
			}

			// ASN
			srcASN := entry["Src ASN"]
			asn := entry["ASN Number"]
			if srcASN != "" || asn != "" {
				event.AddEventDetail(&events.ASN{ASN: asn, ASName: srcASN})
			}

			// IP
			event.IP = getEntryForKeys(entry, []string{"Source IP", "Attacker"})

			// Target
			if dstIP := entry["Destination IP"]; dstIP != "" {
				event.AddEventDetail(&events.Target{IP: dstIP})
			}

			result = append(result, event)
		}
		return result, nil
	}

	// Try URL extraction
	body = strings.ReplaceAll(body, " :", ":")
	if url := common.GetNonEmptyLineAfter(body, "The malicious URL is as follows:"); url != "" {
		eventTemplate.URL = url
		eventTemplate.IP = subject
		return []*events.Event{eventTemplate}, nil
	}

	if url := common.GetNonEmptyLineAfter(body, "The following URL is hosting malicious APK file:"); url != "" {
		eventTemplate.URL = url
		eventTemplate.IP = subject
		return []*events.Event{eventTemplate}, nil
	}

	if strings.Contains(strings.ToLower(subject), "from ip") {
		eventTemplate.IP = subject
		return []*events.Event{eventTemplate}, nil
	}

	// Try regex pattern
	pattern := regexp.MustCompile(`(\S{3}\s+\d+,\s+\d{4}\s+@\s+\d{2}:\d{2}:\d{2})\.\d{3}\s+\S+((\s+\D+)+)\s+(\d+)\s+((\d|\.)+)\s+((\d|\.)+)`)
	matches := pattern.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) >= 7 {
			event := copyEvent(eventTemplate)
			if t, err := parseDate(match[1], []string{"Jan 2, 2006 @ 15:04:05"}); err == nil {
				event.EventDate = t
			}
			event.IP = match[5]
			event.AddEventDetail(&events.Target{IP: match[7]})
			event.AddEventDetail(&events.ASN{ASName: match[2], ASN: match[4]})
			result = append(result, event)
		}
	}

	if len(result) == 0 {
		return []*events.Event{eventTemplate}, nil
	}
	return result, nil
}

func parseBruteForce(serializedEmail *email.SerializedEmail, body, subjectLower string, eventTemplate *events.Event) ([]*events.Event, error) {
	var result []*events.Event
	eventTemplate.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	ips := make(map[string]bool)

	// Check for Src ASN pattern in body
	if strings.Contains(body, "Src ASN") {
		pattern := regexp.MustCompile(`(\S{3}\s+\d+,\s+\d{4}\s+@\s+\d{2}:\d{2}:\d{2})\.\d{3}\s+\S+((\s+\D+)+)\s+(\d+)\s+((\d|\.)+)`)
		matches := pattern.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) >= 6 {
				ip := match[5]
				if !ips[ip] {
					ips[ip] = true
					event := copyEvent(eventTemplate)
					event.IP = ip
					if t, err := parseDate(match[1], []string{"Jan 2, 2006 @ 15:04:05"}); err == nil {
						event.EventDate = t
					}
					event.AddEventDetail(&events.ASN{ASName: match[2], ASN: match[4]})
					result = append(result, event)
				}
			}
		}
		if len(result) > 0 {
			return result, nil
		}
	}

	// Try CSV attachments
	var entries []map[string]string
	if rawCSV, err := common.FindFirstAttachmentWithMimeType(serializedEmail, ".csv"); err == nil {
		entries, _ = parseCSVFromString(rawCSV)
	}

	if entries != nil && len(entries) > 0 {
		for _, entry := range entries {
			event := copyEvent(eventTemplate)
			event.IP = getEntryForKeys(entry, []string{"IP", "Source IP"})

			// Parse date
			dateStr := getEntryForKeys(entry, []string{"timestamp(UTC+0)", "Timestamp"})
			if dateStr != "" {
				parts := strings.Split(dateStr, ".")
				if len(parts) > 0 {
					if t, err := parseDate(parts[0], []string{"Jan 2, 2006 @ 15:04:05"}); err == nil {
						event.EventDate = t
					}
				}
			}

			// Ports
			if portStr := getEntryForKeys(entry, []string{"source_port"}); portStr != "" {
				if port, err := common.ParsePort(portStr); err == nil {
					event.Port = port
				}
			}

			if dstPort := getEntryForKeys(entry, []string{"destination_port"}); dstPort != "" {
				event.AddEventDetail(&events.Target{Port: dstPort})
			}

			// ASN
			asn := getEntryForKeys(entry, []string{"Src ASN"})
			asnNumber := getEntryForKeys(entry, []string{"ASN Number"})
			if asn != "" || asnNumber != "" {
				event.AddEventDetail(&events.ASN{ASName: asn, ASN: asnNumber})
			}

			result = append(result, event)
		}
		return result, nil
	}

	// Try IPs from subject
	if ipsStr := common.FindStringWithoutMarkers(subjectLower, "ips", ";"); ipsStr != "" {
		ipsStr = strings.ReplaceAll(ipsStr, " &", ",")
		ipList := strings.Split(ipsStr, ",")
		for _, ip := range ipList {
			event := copyEvent(eventTemplate)
			event.IP = strings.TrimSpace(ip)
			result = append(result, event)
		}
		return result, nil
	}

	// Try single IP from subject
	if ip := common.FindStringWithoutMarkers(subjectLower, "ip", "ref"); ip != "" {
		eventTemplate.IP = strings.ReplaceAll(ip, "[.]", ".")
		return []*events.Event{eventTemplate}, nil
	}

	return []*events.Event{eventTemplate}, nil
}

func parsePortscan(serializedEmail *email.SerializedEmail, body, subject string, eventTemplate *events.Event) ([]*events.Event, error) {
	var result []*events.Event
	eventTemplate.EventTypes = []events.EventType{events.NewPortScan()}
	ips := make(map[string]bool)

	// Try CSV attachments
	var entries []map[string]string
	if rawCSV, err := common.FindFirstAttachmentWithMimeType(serializedEmail, ".csv"); err == nil {
		// Check if tab-delimited
		if strings.Contains(rawCSV, "\t") {
			reader := csv.NewReader(strings.NewReader(rawCSV))
			reader.Comma = '\t'
			records, _ := reader.ReadAll()
			if len(records) > 0 {
				headers := records[0]
				for i := 1; i < len(records); i++ {
					row := make(map[string]string)
					for j, value := range records[i] {
						if j < len(headers) {
							row[headers[j]] = value
						}
					}
					entries = append(entries, row)
				}
			}
		} else {
			entries, _ = parseCSVFromString(rawCSV)
		}
	}

	if entries != nil && len(entries) > 0 {
		for _, entry := range entries {
			ip := getEntryForKeys(entry, []string{"Source IP", "source_ip", "來源IP", "Source address", "Src IP", "IP"})
			if ip != "" && !ips[ip] {
				ips[ip] = true
				event := copyEvent(eventTemplate)
				event.IP = ip

				// Parse dates
				if dateStr := entry["Start Time"]; dateStr != "" {
					if t, err := parseDate(dateStr, []string{"Jan 2, 2006, 15:04:05 PM"}); err == nil {
						event.EventDate = t
					}
				} else if dateStr := entry["Timestamp"]; dateStr != "" {
					parts := strings.Split(dateStr, ".")
					if len(parts) > 0 {
						if t, err := parseDate(parts[0], []string{"Jan 2, 2006 @ 15:04:05"}); err == nil {
							event.EventDate = t
						}
					}
				} else if dateStr := entry["觸發時間"]; dateStr != "" {
					parts := strings.Split(dateStr, ".")
					if len(parts) > 0 {
						event.EventDate, _ = parseDate(parts[0], []string{"2006-01-02 15:04:05"})
					}
				}

				// Port
				if portStr := getEntryForKeys(entry, []string{"Source Port", "source_port", "Src Port"}); portStr != "" {
					if port, err := common.ParsePort(portStr); err == nil {
						event.Port = port
					}
				}

				// ASN
				asnName := entry["Src ASN"]
				asn := getEntryForKeys(entry, []string{"ASN Number", "ASN"})
				if asnName != "" && asn == "" {
					asn = asnName
					asnName = ""
				}
				if asn != "" || asnName != "" {
					event.AddEventDetail(&events.ASN{ASN: asn, ASName: asnName})
				}

				// Target
				dstIP := getEntryForKeys(entry, []string{"Destination IP", "destination_ip", "Destination address"})
				dstPort := getEntryForKeys(entry, []string{"Destination Port", "destination_port", "目的Port"})
				if dstIP != "" || dstPort != "" {
					event.AddEventDetail(&events.Target{IP: dstIP, Port: dstPort})
				}

				result = append(result, event)
			}
		}

		if len(result) == 0 {
			eventTemplate.IP = common.FindStringWithoutMarkers(body, "IP", "")
			return []*events.Event{eventTemplate}, nil
		}
		return result, nil
	}

	// Try regex pattern
	if strings.Contains(body, "Timestamp Country Name Src ASN ASN Number Source IP") {
		pattern := regexp.MustCompile(`(\S{3}\s+\d+,\s+\d{4}\s+@\s+\d{2}:\d{2}:\d{2})\.\d{3}\s+\S+\s+(.*)\s+(\d+)\s+((\d|\.)+)`)
		matches := pattern.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) >= 5 {
				ip := match[4]
				if !ips[ip] {
					ips[ip] = true
					event := copyEvent(eventTemplate)
					event.IP = ip
					if t, err := parseDate(match[1], []string{"Jan 2, 2006 @ 15:04:05"}); err == nil {
						event.EventDate = t
					}
					event.AddEventDetail(&events.ASN{ASName: match[2], ASN: match[3]})
					result = append(result, event)
				}
			}
		}
		if len(result) > 0 {
			return result, nil
		}
	}

	// Fallback
	if ip := common.FindStringWithoutMarkers(body, "IP address", ""); ip == "" {
		ip = strings.ReplaceAll(subject, "[.]", ".")
		eventTemplate.IP = ip
	} else {
		eventTemplate.IP = ip
	}
	return []*events.Event{eventTemplate}, nil
}

func parseCompromisedServer(serializedEmail *email.SerializedEmail, body string, eventTemplate *events.Event) ([]*events.Event, error) {
	var result []*events.Event
	eventTemplate.EventTypes = []events.EventType{events.NewCompromisedServer()}

	// Try CSV
	var entries []map[string]string
	if rawCSV, err := common.FindFirstAttachmentWithMimeType(serializedEmail, ".csv"); err == nil {
		entries, _ = parseCSVFromString(rawCSV)
	}

	if entries != nil && len(entries) > 0 {
		for _, entry := range entries {
			event := copyEvent(eventTemplate)
			if ip := entry["IP"]; ip != "" {
				event.IP = ip
			} else {
				event.IP = fmt.Sprintf("%v", entry)
			}

			if portStr := entry["Port"]; portStr != "" {
				if port, err := common.ParsePort(portStr); err == nil {
					event.Port = port
				}
			}

			if timestamp := entry["Timestamp"]; timestamp != "" {
				event.EventDate, _ = parseDate(timestamp, []string{
					"2006-01-02 15:04:05",
					"Jan 2, 2006 @ 15:04:05",
				})
			}

			result = append(result, event)
		}
		return result, nil
	}

	// Try IP extraction
	if ip := common.FindStringWithoutMarkers(body, "IP address", "under your"); ip != "" {
		eventTemplate.IP = strings.ReplaceAll(ip, "[.]", ".")
		return []*events.Event{eventTemplate}, nil
	}

	// Try IP block
	if ipBlock := common.GetBlockAfterWithStop(body, "IP address:", ""); len(ipBlock) > 0 {
		for _, ip := range ipBlock {
			event := copyEvent(eventTemplate)
			event.IP = ip
			result = append(result, event)
		}
		if len(result) > 0 {
			return result, nil
		}
	}

	return []*events.Event{eventTemplate}, nil
}

func parseDDoS(body, subject string, event *events.Event) ([]*events.Event, error) {
	event.EventTypes = []events.EventType{events.NewDDoS()}
	event.IP = subject
	if dstIP := common.FindStringWithoutMarkers(body, "The targeted IP address was", ""); dstIP != "" {
		event.AddEventDetail(&events.Target{IP: dstIP})
	}
	return []*events.Event{event}, nil
}

func parseBotnet(serializedEmail *email.SerializedEmail, body string, eventTemplate *events.Event) ([]*events.Event, error) {
	var result []*events.Event
	body = strings.ReplaceAll(body, " :", ":")
	botType := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Malware:", ""))
	eventTemplate.EventTypes = []events.EventType{events.NewBot(botType)}

	// Try CSV
	if rawCSV, err := common.FindFirstAttachmentWithMimeType(serializedEmail, ".csv"); err == nil {
		entries, err := parseCSVFromString(rawCSV)
		if err == nil {
			ips := make(map[string]bool)
			for _, entry := range entries {
				ip := entry["Source Ip"]
				if ip != "" && !ips[ip] {
					ips[ip] = true
					event := copyEvent(eventTemplate)
					event.IP = ip

					// Date
					if dateStr := strings.TrimSpace(entry["Time"]); dateStr != "" {
						if t, err := parseDate(dateStr, []string{"02-01-2006 15:04:05"}); err == nil {
							event.EventDate = t
						}
					}

					// ASN
					if asn := entry["Source ASN"]; asn != "" {
						event.AddEventDetail(&events.ASN{ASN: asn})
					}

					// Port
					if portStr := entry["Source Port"]; portStr != "" {
						if port, err := common.ParsePort(portStr); err == nil {
							event.Port = port
						}
					}

					// Target
					dstIP := entry["Destination IP"]
					dstPort := entry["Destination Port"]
					if dstIP != "" || dstPort != "" {
						event.AddEventDetail(&events.Target{IP: dstIP, Port: dstPort})
					}

					result = append(result, event)
				}
			}
			return result, nil
		}
	}

	// Fallback to body extraction
	eventTemplate.IP = strings.ReplaceAll(common.FindStringWithoutMarkers(body, "IP address:", ""), "[.]", ".")
	eventTemplate.Port, _ = common.ParsePort(strings.TrimSpace(common.FindStringWithoutMarkers(body, "Port:", "")))

	if firstSeen := strings.TrimSpace(common.FindStringWithoutMarkers(body, "First seen:", "")); firstSeen != "" {
		eventTemplate.EventDate, _ = parseDate(firstSeen, []string{
			"2006-01-02 15:04:05",
			"02-01-2006 15:04:05",
		})
	}

	if proof := common.FindStringWithoutMarkers(body, "Proof:", "-"); proof != "" {
		evidence := &events.Evidence{}
		evidence.AddEvidence(events.UrlStore{URL: proof})
		eventTemplate.AddEventDetail(evidence)
	}

	return []*events.Event{eventTemplate}, nil
}

func parseOpen(body string, event *events.Event) ([]*events.Event, error) {
	event.EventTypes = []events.EventType{events.NewOpen("")}
	event.URL = common.GetNonEmptyLineAfter(body, "Vulnerable URL:")
	return []*events.Event{event}, nil
}

func parseDefacement(body, subject string, eventTemplate *events.Event) ([]*events.Event, error) {
	var result []*events.Event
	body = strings.ReplaceAll(body, "=20", "")
	eventTemplate.EventTypes = []events.EventType{events.NewDefacement()}
	eventTemplate.IP = subject

	urlBlock := common.GetBlockAfterWithStop(body, "The URLs of the defaced websites are:", "")
	for _, url := range urlBlock {
		event := copyEvent(eventTemplate)
		event.URL = url
		result = append(result, event)
	}

	if len(result) == 0 {
		return []*events.Event{eventTemplate}, nil
	}
	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
