package jpcert

import (
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

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	var date *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		date = email.ParseDate(dateHeaders[0])
	}

	// Extract external ID from subject if present
	var externalID *events.ExternalID
	if strings.HasPrefix(subject, "JPCERT#") {
		parts := strings.Fields(subject)
		if len(parts) > 0 {
			externalID = &events.ExternalID{ID: parts[0]}
		}
	}

	subjectLower := strings.ToLower(subject)
	bodyLower := strings.ToLower(body)

	// Determine event type based on subject and body
	if strings.Contains(subjectLower, "phishing") {
		return parsePhishing(body, date, externalID)
	} else if strings.Contains(subject, "Possible Computer Security Incident") && strings.Contains(bodyLower, "phishing") {
		return parsePhishingAlternate(body, date, externalID)
	} else if strings.Contains(subject, "Possible Computer Security Incident") && strings.Contains(bodyLower, "scanning") {
		return parsePortScan(body, serializedEmail, externalID)
	} else if strings.Contains(subject, "Possible Computer Security Incident") && strings.Contains(bodyLower, "malware") {
		return parseMalware(body, date, externalID)
	} else if strings.Contains(subjectLower, "unauthorized access") && strings.Contains(bodyLower, "logged") {
		return parseLoginAttack(body, serializedEmail, externalID)
	}

	return nil, common.NewNewTypeError(subject)
}

func parsePhishing(body string, date *time.Time, externalID *events.ExternalID) ([]*events.Event, error) {
	urls := common.GetContinuousLinesUntilEmptyLine(body, "fraudulent web site:")
	if len(urls) == 0 {
		return nil, common.NewParserError("no URLs found after 'fraudulent web site:'")
	}

	// Trim URLs
	for i := range urls {
		urls[i] = strings.TrimSpace(urls[i])
	}

	// Check if last URL is actually an IP
	var ip string
	if len(urls) > 0 {
		possibleIP := common.ExtractOneIP(urls[len(urls)-1])
		if possibleIP != "" {
			ip = possibleIP
			urls = urls[:len(urls)-1]
		}
	}

	// If no IP found, try to extract from line after last URL
	if ip == "" && len(urls) > 0 {
		nextLine := common.GetNonEmptyLineAfter(body, urls[len(urls)-1])
		ip = common.ExtractOneIP(nextLine)
	}

	// Get legitimate URL
	legitimateURL := common.GetLineAfter(body, "legitimate web site:", 1)
	legitimateURL = strings.TrimSpace(legitimateURL)
	legitimateURL = common.CleanURL(legitimateURL)

	var eventsList []*events.Event
	for _, url := range urls {
		event := events.NewEvent("jpcert")
		event.EventDate = date

		if externalID != nil {
			event.AddEventDetail(externalID)
		}

		url = common.CleanURL(strings.TrimSpace(url))
		event.IP = ip
		event.URL = url

		phishing := events.NewPhishing()
		phishing.OfficialURL = legitimateURL
		event.EventTypes = []events.EventType{phishing}

		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

func parsePhishingAlternate(body string, date *time.Time, externalID *events.ExternalID) ([]*events.Event, error) {
	urls := common.GetContinuousLinesUntilEmptyLine(body, "The link of suspicious URL:")
	if len(urls) == 0 {
		return nil, common.NewParserError("no URLs found after 'The link of suspicious URL:'")
	}

	// Trim URLs
	for i := range urls {
		urls[i] = strings.TrimSpace(urls[i])
	}

	// Check if last URL is actually an IP
	var ip string
	if len(urls) > 0 {
		possibleIP := common.ExtractOneIP(urls[len(urls)-1])
		if possibleIP != "" {
			ip = possibleIP
			urls = urls[:len(urls)-1]
		}
	}

	// If no IP found, try to extract from line after last URL
	if ip == "" && len(urls) > 0 {
		nextLine := common.GetNonEmptyLineAfter(body, urls[len(urls)-1])
		ip = common.ExtractOneIP(nextLine)
	}

	// Get legitimate URL
	legitimateURL := common.GetLineAfter(body, "legitimate web site:", 1)
	legitimateURL = strings.TrimSpace(legitimateURL)
	legitimateURL = common.CleanURL(legitimateURL)

	var eventsList []*events.Event
	for _, url := range urls {
		event := events.NewEvent("jpcert")
		event.EventDate = date

		if externalID != nil {
			event.AddEventDetail(externalID)
		}

		url = common.CleanURL(strings.TrimSpace(url))
		event.IP = ip
		event.URL = url

		phishing := events.NewPhishing()
		phishing.OfficialURL = legitimateURL
		event.EventTypes = []events.EventType{phishing}

		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

func parsePortScan(body string, serializedEmail *email.SerializedEmail, externalID *events.ExternalID) ([]*events.Event, error) {
	var eventsList []*events.Event

	// Check for CSV format
	if !strings.Contains(body, "IP,timestamp(UTC+0),source_port,destination_port") {
		// Parse simple format
		portProtocol := common.FindStringWithoutMarkers(body, "Destination Port/Protocol :", "")
		parts := strings.Split(portProtocol, "/")
		if len(parts) != 2 {
			return nil, common.NewParserError("invalid port/protocol format")
		}

		port, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, common.NewParserError("invalid port: " + err.Error())
		}

		protocol := strings.TrimSpace(parts[1])

		event := events.NewEvent("jpcert")

		var date *time.Time
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			date = email.ParseDate(dateHeaders[0])
		}
		event.EventDate = date

		event.IP = common.FindStringWithoutMarkers(body, "Source IP :", "")
		event.Port = port

		destinationIP := common.FindStringWithoutMarkers(body, "Destination IP :", "")
		event.AddEventDetail(&events.Target{IP: destinationIP})
		event.AddEventDetail(&events.TransportProtocol{Protocol: protocol})

		event.EventTypes = []events.EventType{events.NewPortScan()}

		if externalID != nil {
			event.AddEventDetail(externalID)
		}

		return []*events.Event{event}, nil
	}

	// Parse CSV format
	entries := common.GetBlockAround(body, "IP,timestamp(UTC+0),source_port,destination_port")
	if len(entries) <= 1 {
		return nil, common.NewParserError("no CSV entries found")
	}

	// Skip header line
	for _, line := range entries[1:] {
		parts := strings.Split(line, ",")
		if len(parts) != 4 {
			continue
		}

		ip := strings.TrimSpace(parts[0])
		dateStr := strings.TrimSpace(parts[1])
		srcPort := strings.TrimSpace(parts[2])
		dstPort := strings.TrimSpace(parts[3])

		event := events.NewEvent("jpcert")

		// Parse date
		date := email.ParseDate(dateStr)
		event.EventDate = date

		event.IP = ip

		// Parse source port
		if srcPortNum, err := strconv.Atoi(srcPort); err == nil {
			event.Port = srcPortNum
		}

		// Add destination port as target
		event.AddEventDetail(&events.Target{Port: dstPort})

		event.EventTypes = []events.EventType{events.NewPortScan()}

		if externalID != nil {
			event.AddEventDetail(externalID)
		}

		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

func parseMalware(body string, date *time.Time, externalID *events.ExternalID) ([]*events.Event, error) {
	event := events.NewEvent("jpcert")

	data := common.GetBlockAround(body, "link of suspicious file URL")
	if len(data) < 2 {
		return nil, common.NewParserError("malware URL not found")
	}

	event.URL = common.CleanURL(data[1])

	if len(data) >= 3 {
		event.IP = data[2]
	}

	event.EventDate = date

	if externalID != nil {
		event.AddEventDetail(externalID)
	}

	event.EventTypes = []events.EventType{events.NewMalware("")}

	return []*events.Event{event}, nil
}

func parseLoginAttack(body string, serializedEmail *email.SerializedEmail, externalID *events.ExternalID) ([]*events.Event, error) {
	var eventsList []*events.Event
	bodyLower := strings.ToLower(body)

	var fallbackDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		fallbackDate = email.ParseDate(dateHeaders[0])
	}

	// Extract malware name
	malwareName := common.FindStringWithoutMarkers(body, "malware is called \"", "\"")

	// Extract destination IP
	destinationIPStr := common.FindStringWithoutMarkers(bodyLower, "destination ip", "")
	destinationIPStr = strings.ReplaceAll(destinationIPStr, ":", " ")
	destinationIPStr = strings.TrimSpace(destinationIPStr)

	// Extract timezone
	timezoneStr := common.FindStringWithoutMarkers(bodyLower, "timezone:", "")
	timezoneParts := strings.Split(timezoneStr, "+")
	var timezone string
	if len(timezoneParts) > 1 {
		tzFields := strings.Fields(timezoneParts[1])
		if len(tzFields) > 0 {
			timezone = tzFields[0]
		}
	}

	// Extract IPs from "related ip address" block
	ipBlock := common.GetBlockAround(bodyLower, "related ip address")
	if len(ipBlock) == 0 {
		return nil, common.NewParserError("no ip found")
	}

	var ips []string
	for _, line := range ipBlock {
		if ip := common.ExtractOneIP(line); ip != "" {
			ips = append(ips, ip)
		}
	}

	if len(ips) == 0 {
		return nil, common.NewParserError("no ip found")
	}

	for _, ip := range ips {
		event := events.NewEvent("jpcert")
		event.IP = ip

		event.AddEventDetail(&events.Target{IP: destinationIPStr})

		// Set event type based on malware presence
		if malwareName != "" {
			event.EventTypes = []events.EventType{events.NewMalware(malwareName)}
		} else {
			event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
		}

		if externalID != nil {
			event.AddEventDetail(externalID)
		}

		// Try to extract date for this specific IP
		ipMarker := "ip=" + ip
		if strings.Contains(bodyLower, ipMarker) {
			dateLine := common.GetNonEmptyLineAfter(bodyLower, ipMarker)
			if idx := strings.Index(dateLine, "["); idx != -1 {
				dateLine = dateLine[:idx]
			}
			dateLine = strings.TrimSpace(dateLine)
			if timezone != "" {
				dateLine = dateLine + " +" + timezone
			}
			parsedDate := email.ParseDate(dateLine)
			if parsedDate != nil {
				event.EventDate = parsedDate
			}
		}

		// Use fallback date if no specific date found
		if event.EventDate == nil {
			event.EventDate = fallbackDate
		}

		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
