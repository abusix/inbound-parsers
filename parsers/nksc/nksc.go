package nksc

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	var allEvents []*events.Event

	// Check for CSV attachments in parts first
	if len(serializedEmail.Parts) > 0 {
		for _, part := range serializedEmail.Parts {
			if part.Headers != nil {
				if contentType, ok := part.Headers["content-type"]; ok {
					for _, ct := range contentType {
						if strings.Contains(ct, ".txt") {
							// Get part body
							var partBody string
							switch body := part.Body.(type) {
							case string:
								partBody = body
							case []byte:
								partBody = string(body)
							default:
								continue
							}

							lines := strings.Split(partBody, "\n")
							if len(lines) < 2 {
								continue
							}

							// Skip first empty line if present
							startIdx := 0
							if strings.TrimSpace(lines[0]) == "" && len(lines) > 1 {
								startIdx = 1
							}

							header := lines[startIdx]
							if strings.Contains(header, "IP,timestamp(UTC+0),source_port,destination_port") {
								events, err := parseSSHBruteForce(lines[startIdx+1:])
								if err != nil {
									return nil, err
								}
								return events, nil
							} else if strings.Contains(header, "asn,ip,timestamp,malware,src_port,dst_ip,dst_port,dst_host,proto") {
								events, err := parseMalware(lines[startIdx+1:])
								if err != nil {
									return nil, err
								}
								return events, nil
							} else {
								return nil, fmt.Errorf("csv headers changed, adapt the parser")
							}
						}
					}
				}
			}
		}
	}

	// Parse body-based formats
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Replace tabs with commas for consistent parsing
	if strings.Contains(body, "\t") {
		body = strings.ReplaceAll(body, "\t", ",")
	}

	// Try different CSV field formats
	fields := []string{
		`asn,"ip","timestamp","malware","src_port","dst_ip","dst_port","dst_host","proto"`,
		"asn,ip,timestamp,malware,src_port,dst_ip,dst_port,dst_host,proto",
		"IP,timestamp(UTC+0),source_port,destination_port",
	}

	alreadyParsed := false
	for i, field := range fields {
		if lines := getLines(field, body); lines != nil {
			alreadyParsed = true
			if i < 2 {
				// Malware format
				events, err := parseMalware(lines)
				if err != nil {
					return nil, err
				}
				allEvents = events
			} else {
				// SSH brute force format
				events, err := parseSSHBruteForce(lines)
				if err != nil {
					return nil, err
				}
				allEvents = events
			}
			break
		}
	}

	if !alreadyParsed {
		subject, err := common.GetSubject(serializedEmail, true)
		if err != nil {
			return nil, err
		}
		subjectLower := strings.ToLower(subject)
		bodyLower := strings.ToLower(body)

		if strings.Contains(subjectLower, "web shell") {
			return parseWebshell(serializedEmail, body, subject)
		}

		if strings.Contains(subjectLower, "phishing") || strings.Contains(bodyLower, "phishing") {
			return parsePhishing(serializedEmail, body, subject)
		}

		if strings.Contains(subjectLower, "sapm") || strings.Contains(subjectLower, "spam") {
			return parseSpam(serializedEmail, subject)
		}

		if strings.Contains(subjectLower, "cve") {
			return parseCVE(serializedEmail, subject, body)
		}

		if strings.Contains(subjectLower, "malware") {
			return parseMalwareHosting(serializedEmail, body, subject)
		}
	}

	if len(allEvents) == 0 {
		return nil, fmt.Errorf("no event created")
	}

	return allEvents, nil
}

func getLines(fields, body string) []string {
	if !strings.Contains(body, fields) {
		return nil
	}

	bodyReplace := strings.Replace(body, fields, fields+"\n", 1)
	lines := common.GetBlockAfterWithStop(bodyReplace, fields, "")
	return lines
}

func parseSSHBruteForce(lines []string) ([]*events.Event, error) {
	var result []*events.Event

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) != 4 {
			continue
		}

		ip := strings.TrimSpace(parts[0])
		timestamp := strings.TrimSpace(parts[1])
		srcPort := strings.TrimSpace(parts[2])
		dstPort := strings.TrimSpace(parts[3])

		event := events.NewEvent("nksc")
		event.IP = ip
		event.EventDate = email.ParseDate(timestamp)
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

		if port, err := strconv.Atoi(srcPort); err == nil {
			event.Port = port
		}

		event.AddEventDetail(&events.Target{Port: dstPort})
		result = append(result, event)
	}

	return result, nil
}

func parseMalware(lines []string) ([]*events.Event, error) {
	var result []*events.Event

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var parts []string
		properlyFormatted := false

		// Try comma-separated first
		parts = strings.Split(line, ",")
		if len(parts) == 9 {
			properlyFormatted = true
		} else {
			// Try tab-separated
			parts = strings.Split(line, "\t")
			if len(parts) == 9 {
				properlyFormatted = true
			}
		}

		if !properlyFormatted {
			continue
		}

		asn := strings.Trim(strings.TrimSpace(parts[0]), `"`)
		ip := strings.Trim(strings.TrimSpace(parts[1]), `"`)
		ts := strings.Trim(strings.TrimSpace(parts[2]), `"`)
		mw := strings.Trim(strings.TrimSpace(parts[3]), `"`)
		srcPort := strings.Trim(strings.TrimSpace(parts[4]), `"`)
		dstIP := strings.Trim(strings.TrimSpace(parts[5]), `"`)
		dstPort := strings.Trim(strings.TrimSpace(parts[6]), `"`)
		dstHost := strings.Trim(strings.TrimSpace(parts[7]), `"`)
		prot := strings.Trim(strings.TrimSpace(parts[8]), `"`)

		event := events.NewEvent("nksc")
		event.AddEventDetail(&events.ASN{ASN: asn})
		event.IP = ip
		event.EventDate = email.ParseDate(ts)

		// Check if it's a bot
		if strings.Contains(strings.ToLower(mw), "bot") {
			event.EventTypes = []events.EventType{events.NewBot("")}
		} else {
			event.EventTypes = []events.EventType{events.NewMalware(mw)}
		}

		if port, err := strconv.Atoi(srcPort); err == nil {
			event.Port = port
		}

		event.AddEventDetail(&events.Target{IP: dstIP, Port: dstPort})
		event.URL = dstHost
		event.AddEventDetail(&events.TransportProtocol{Protocol: prot})

		result = append(result, event)
	}

	return result, nil
}

func parseCVE(serializedEmail *email.SerializedEmail, subject, body string) ([]*events.Event, error) {
	var result []*events.Event

	// Extract CVE name
	cveName := common.FindStringWithoutMarkers(subject, "(cve-", ")")
	if cveName == "" {
		cveName = common.FindStringWithoutMarkers(subject, "(CVE-", ")")
	}

	var dateHeader string
	if serializedEmail.Headers != nil {
		if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
			dateHeader = dates[0]
		}
	}

	// Find marker for affected sites
	marker := ""
	if strings.Contains(body, "Identifikuotos svetainės:") {
		marker = "Identifikuotos svetainės:"
	} else if strings.Contains(body, "tinkle:") {
		marker = "tinkle:"
	} else if strings.Contains(body, "Nustatyti įrenginiai") {
		marker = "Nustatyti įrenginiai"
	} else {
		return nil, fmt.Errorf("unknown CVE format in subject: %s", subject)
	}

	affected := common.GetBlockAround(body, marker)
	if len(affected) == 0 {
		return result, nil
	}

	// Skip first line (the marker line itself)
	for i := 1; i < len(affected); i++ {
		line := affected[i]
		event := events.NewEvent("nksc")
		event.EventTypes = []events.EventType{events.NewCVE(cveName, "", "")}
		event.EventDate = email.ParseDate(dateHeader)

		// Extract entity (before parenthesis if present)
		entity := line
		if idx := strings.Index(line, "("); idx != -1 {
			entity = strings.TrimSpace(line[:idx])
		}

		// Try to extract IP
		if ip := common.ExtractOneIP(entity); ip != "" {
			event.IP = ip
		} else {
			event.URL = entity
		}

		result = append(result, event)
	}

	return result, nil
}

func parseSpam(serializedEmail *email.SerializedEmail, subject string) ([]*events.Event, error) {
	var result []*events.Event

	event := events.NewEvent("nksc")

	// Try to parse subject as IP
	ip := common.IsIP(subject)
	if ip != "" {
		event.IP = ip
	} else {
		// No valid IP, don't create event
		return result, nil
	}

	var dateHeader string
	if serializedEmail.Headers != nil {
		if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
			dateHeader = dates[0]
		}
	}

	event.EventDate = email.ParseDate(dateHeader)
	event.EventTypes = []events.EventType{events.NewSpam()}

	result = append(result, event)
	return result, nil
}

func parsePhishing(serializedEmail *email.SerializedEmail, body, subject string) ([]*events.Event, error) {
	var result []*events.Event

	event := events.NewEvent("nksc")

	// Try to parse subject as IP
	ip := common.IsIP(subject)
	if ip != "" {
		event.IP = ip
	} else {
		// Try to extract IP from hxxps string in body
		hxxpsStr := common.FindStringWithoutMarkers(body, "hxxps", "")
		if hxxpsStr != "" {
			ip = common.ExtractOneIP(hxxpsStr)
			if ip != "" {
				event.IP = ip
			}
		}
	}

	// Try to find URL after "about this page:"
	url := ""
	lines := common.GetBlockAfterWithStop(body, "about this page:", "")
	for _, line := range lines {
		if common.IsURL(line) {
			url = line
			break
		}
	}

	event.URL = url
	event.EventTypes = []events.EventType{events.NewPhishing()}

	var dateHeader string
	if serializedEmail.Headers != nil {
		if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
			dateHeader = dates[0]
		}
	}
	event.EventDate = email.ParseDate(dateHeader)

	// Reports are unreliable, fail quietly if no IP or URL is found
	if event.IP != "" || event.URL != "" {
		result = append(result, event)
	}

	return result, nil
}

func parseWebshell(serializedEmail *email.SerializedEmail, body, subject string) ([]*events.Event, error) {
	var result []*events.Event

	event := events.NewEvent("nksc")

	// Try to parse subject as IP
	ip := common.IsIP(subject)
	if ip != "" {
		event.IP = ip
	} else {
		// Try to extract IP from hxxps string in body
		hxxpsStr := common.FindStringWithoutMarkers(body, "hxxps", "")
		if hxxpsStr != "" {
			ip = common.ExtractOneIP(hxxpsStr)
			if ip != "" {
				event.IP = ip
			}
		}
	}

	// Replace hxxp with http
	body = strings.ReplaceAll(body, "hxxp", "http")
	url := common.FindString(body, "http", " ")
	event.URL = strings.TrimSpace(url)
	event.EventTypes = []events.EventType{events.NewCompromisedWebsite("")}

	var dateHeader string
	if serializedEmail.Headers != nil {
		if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
			dateHeader = dates[0]
		}
	}
	event.EventDate = email.ParseDate(dateHeader)

	// Reports are unreliable, fail quietly if no IP or URL is found
	if event.IP != "" || event.URL != "" {
		result = append(result, event)
	}

	return result, nil
}

func parseMalwareHosting(serializedEmail *email.SerializedEmail, body, subject string) ([]*events.Event, error) {
	event := events.NewEvent("nksc")

	var dateHeader string
	if serializedEmail.Headers != nil {
		if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
			dateHeader = dates[0]
		}
	}
	event.EventDate = email.ParseDate(dateHeader)

	// Try to parse subject as IP
	ip := common.IsIP(subject)
	if ip != "" {
		event.IP = ip
	} else {
		// Try to extract from hxxps
		hxxpsStr := common.FindStringWithoutMarkers(body, "hxxps", "")
		if hxxpsStr != "" {
			event.IP = hxxpsStr
		}
	}

	event.EventTypes = []events.EventType{events.NewMalwareHosting()}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
