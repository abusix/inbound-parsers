// Package orange implements the Orange parser for reconnaissance and SNMP attack reports
package orange

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the Orange parser
type Parser struct{}

// Parse parses emails from @orange.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get body and subject
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	body = strings.ToLower(body)

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	subject = strings.ToLower(subject)

	// Route to appropriate parser based on subject
	if strings.Contains(subject, "reconnaissance") {
		return parseReconnaissance(body, serializedEmail)
	} else if strings.Contains(subject, "snmp attempt") {
		return parseSNMPAttempt(body, serializedEmail)
	}

	return nil, common.NewParserError("unknown subject type: " + subject)
}

// parseReconnaissance handles reconnaissance/port scan events
func parseReconnaissance(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Extract CIDR block
	cidrLines := common.GetBlockAfterWithStop(body, "cidr", "organization")
	if len(cidrLines) == 0 {
		return nil, common.NewParserError("no CIDR block found")
	}

	// Split IPs from lines (handle 'and' and ',' separators)
	var ips []string
	for _, line := range cidrLines {
		line = strings.ReplaceAll(line, "\"", "")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Split by 'and' or ','
		if strings.Contains(line, "and") {
			parts := strings.Split(line, "and")
			for _, part := range parts {
				ip := strings.TrimSpace(part)
				if ip != "" {
					ips = append(ips, ip)
				}
			}
		} else if strings.Contains(line, ",") {
			parts := strings.Split(line, ",")
			for _, part := range parts {
				ip := strings.TrimSpace(part)
				if ip != "" {
					ips = append(ips, ip)
				}
			}
		} else {
			ips = append(ips, line)
		}
	}

	if len(ips) == 0 {
		return nil, common.NewParserError("no IPs found in CIDR block")
	}

	// Get event date from email headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	var eventsList []*events.Event
	for _, ip := range ips {
		event := events.NewEvent("orange")
		event.IP = ip
		event.EventTypes = []events.EventType{events.NewPortScan()}
		event.EventDate = eventDate
		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no events created")
	}

	return eventsList, nil
}

// parseSNMPAttempt handles SNMP authentication failure events
func parseSNMPAttempt(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Extract sample logs block
	logLines := common.GetBlockAfterWithStop(body, "sample logs:", "")
	if len(logLines) == 0 {
		return nil, common.NewParserError("no sample logs found")
	}

	// Get report date for year context
	var reportDate time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
			reportDate = *parsedDate
		} else {
			reportDate = time.Now()
		}
	} else {
		reportDate = time.Now()
	}

	var eventsList []*events.Event

	// Parse each log line
	for _, logLine := range logLines {
		// Normalize whitespace
		logLine = regexp.MustCompile(`\s+`).ReplaceAllString(logLine, " ")
		logLine = strings.TrimSpace(logLine)

		if !strings.Contains(logLine, "authentication failure") {
			return nil, common.NewParserError("unexpected log format: " + logLine)
		}

		// Split log line into parts
		parts := strings.Fields(logLine)
		if len(parts) < 4 {
			continue // Skip malformed lines
		}

		// Parse event date (first 3 parts: "Nov 15 10:30:45")
		if len(parts) < 3 {
			continue
		}
		eventDateStr := strings.Join(parts[0:3], " ")
		eventDate, err := parseLogDate(eventDateStr, reportDate.Year())
		if err != nil {
			continue // Skip if date parsing fails
		}

		// Extract source IP (last part)
		sourceIP := parts[len(parts)-1]

		// Extract destination IP (4th part, index 3)
		var dstIP string
		if len(parts) > 3 {
			dstIP = parts[3]
		}

		// Create event
		event := events.NewEvent("orange")
		event.IP = sourceIP
		event.EventTypes = []events.EventType{events.NewAuthFailure()}
		event.EventDate = eventDate

		// Add target detail
		if dstIP != "" {
			event.AddEventDetail(&events.Target{
				IP:      dstIP,
				Service: "snmp",
			})
		}

		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no events created from logs")
	}

	return eventsList, nil
}

// parseLogDate parses a log date in format "Nov 15 10:30:45" with a given year
// Returns time in CET (UTC+1) timezone
func parseLogDate(dateStr string, year int) (*time.Time, error) {
	// Add year to the date string
	fullDateStr := fmt.Sprintf("%s %d", dateStr, year)

	// Parse the date
	loc := time.FixedZone("CET", 3600) // UTC+1
	parsedDate, err := time.ParseInLocation("Jan 2 15:04:05 2006", fullDateStr, loc)
	if err != nil {
		return nil, err
	}

	return &parsedDate, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
