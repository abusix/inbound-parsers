// Package skhron implements the skhron parser
// This is a 100% exact Go translation of Python's skhron.py
package skhron

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the skhron parser
type Parser struct{}

var (
	// dataPattern matches: timestamp source_ip source_port dest_ip dest_port
	// Example: 2024-10-18T12:34:56.789Z 192.168.1.1 1234 192.168.1.2 80
	dataPattern = regexp.MustCompile(
		`(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+` +
			`(\S*\d+\.\d+\.\d+\.\d+\S*)\s+` +
			`(\d+)\s+` +
			`(\S*\d+[.x]\d+[.x]\d+[.x]\d+\S*)\s+` +
			`(\d+)`,
	)

	sourceIPPattern = regexp.MustCompile(`(?i)(\[?source_ip\]?:)\s*(?P<src_ip>.*)`)
	destIPsPattern  = regexp.MustCompile(`(?i)(\[?destination_ip_addresses\]?:)\s*(?P<dst_ips>.*)`)
	destPortPattern = regexp.MustCompile(`(?i)(\[?destination_port\]?:)\s*(?P<dst_port>.*)`)
)

// NewParser creates a new skhron parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses port scan reports from skhron
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)

	if strings.Contains(subjectLower, "portscan") {
		// Get date fallback from headers
		dateFallback := ""
		if serializedEmail.Headers != nil {
			if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
				dateFallback = dateHeaders[0]
			}
		}
		return parsePortscan(body, dateFallback)
	}

	return nil, fmt.Errorf("unknown report type in subject: %s", subject)
}

// parsePortscan parses port scan event data
func parsePortscan(body, dateFallback string) ([]*events.Event, error) {
	var result []*events.Event

	// First, try the tabular format with regex pattern
	matches := dataPattern.FindAllStringSubmatch(body, -1)

	if len(matches) > 0 {
		// Use a map to deduplicate matches
		seen := make(map[string]bool)
		var uniqueMatches [][]string

		for _, match := range matches {
			key := strings.Join(match, "|")
			if !seen[key] {
				seen[key] = true
				uniqueMatches = append(uniqueMatches, match)
			}
		}

		for _, match := range uniqueMatches {
			event := events.NewEvent("skhron")
			event.EventTypes = []events.EventType{events.NewPortScan()}

			// Parse event date (ISO 8601 format)
			eventDate, err := time.Parse(time.RFC3339Nano, match[1])
			if err == nil {
				event.EventDate = &eventDate
			}

			// Source IP and port
			event.IP = common.ExtractOneIP(match[2])
			if port, err := common.ParsePort(match[3]); err == nil {
				event.Port = port
			}

			// Destination IP and port (replace 'x' with '.')
			destIP := strings.ReplaceAll(match[4], "x", ".")
			destPort := match[5]

			event.AddEventDetail(&events.Target{
				IP:   common.ExtractOneIP(destIP),
				Port: destPort,
			})

			result = append(result, event)
		}
	} else {
		// Try the key-value format with [field]: markers
		eventTemplate := events.NewEvent("skhron")
		eventTemplate.EventTypes = []events.EventType{events.NewPortScan()}

		// Extract source IP
		if srcIPMatch := sourceIPPattern.FindStringSubmatch(body); len(srcIPMatch) > 0 {
			srcIP := srcIPMatch[len(srcIPMatch)-1] // Get named group
			eventTemplate.IP = common.ExtractOneIP(srcIP)
		} else {
			return nil, fmt.Errorf("source IP not found in body")
		}

		// Parse event date if all date components are present
		if strings.Contains(body, "[date]") && strings.Contains(body, "[time]") && strings.Contains(body, "[timezone]") {
			date := common.FindStringWithoutMarkers(body, "[date]:", "")
			date = strings.TrimSpace(date)

			timeStr := common.FindStringWithoutMarkers(body, "[time]:", "")
			timeStr = strings.TrimSpace(timeStr)

			timezone := common.FindStringWithoutMarkers(body, "[timezone]:", "")
			timezone = strings.TrimSpace(timezone)

			// Combine into ISO 8601 format
			dateTimeStr := fmt.Sprintf("%sT%s%s", date, timeStr, timezone)
			eventDate, err := time.Parse(time.RFC3339, dateTimeStr)
			if err == nil {
				eventTemplate.EventDate = &eventDate
			}
		} else {
			// Use date fallback
			if dateFallback != "" {
				eventTemplate.EventDate = email.ParseDate(dateFallback)
			}
		}

		// Extract destination IPs
		var destIPs []string
		if dstIPsMatch := destIPsPattern.FindStringSubmatch(body); len(dstIPsMatch) > 0 {
			dstIPsStr := dstIPsMatch[len(dstIPsMatch)-1] // Get named group
			// Split by %0A (URL-encoded newline) and filter empty strings
			for _, ip := range strings.Split(dstIPsStr, "%0A") {
				ip = strings.TrimSpace(ip)
				if ip != "" && ip != "\r" {
					destIPs = append(destIPs, ip)
				}
			}
		}

		// Extract destination port
		destPort := ""
		if dstPortMatch := destPortPattern.FindStringSubmatch(body); len(dstPortMatch) > 0 {
			destPort = dstPortMatch[len(dstPortMatch)-1] // Get named group
			// Split by '/' and take first part
			if parts := strings.Split(destPort, "/"); len(parts) > 0 {
				destPort = parts[0]
			}
		}

		// Generate events for each destination IP
		if len(destIPs) > 0 {
			for _, dstIP := range destIPs {
				event := copyEvent(eventTemplate)
				// Replace 'x' with '.' in destination IP
				cleanIP := strings.ReplaceAll(dstIP, "x", ".")
				event.AddEventDetail(&events.Target{
					IP:   common.ExtractOneIP(cleanIP),
					Port: destPort,
				})
				result = append(result, event)
			}
		} else {
			// No destination IPs found, return template as-is
			result = append(result, eventTemplate)
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no port scan events could be parsed")
	}

	return result, nil
}

// copyEvent creates a deep copy of an event (excluding event details)
func copyEvent(template *events.Event) *events.Event {
	event := events.NewEvent(template.Parser)
	event.EventTypes = make([]events.EventType, len(template.EventTypes))
	copy(event.EventTypes, template.EventTypes)
	event.IP = template.IP
	event.Port = template.Port
	event.EventDate = template.EventDate
	return event
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
