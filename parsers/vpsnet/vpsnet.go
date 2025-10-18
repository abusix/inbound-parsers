package vpsnet

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
)

// Matches time formats like: Aug 10 14:23:31
// with any number of white spaces between the date parts
var datePattern = regexp.MustCompile(`[A-Za-z]{3}\s*\d{1,2}\s*\d{2}:\d{2}:\d{2}`)

// Matches valid IP addresses with port separated using ':' or '.'
// Example: 138.68.254.243:39181
var ipPattern = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[.|:](\d+)`)

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

	// Get date from email header
	var headerDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		headerDate = email.ParseDate(dateHeaders[0])
	}
	if headerDate == nil {
		return nil, fmt.Errorf("no date header found")
	}

	var targetIP string
	var targetPort string
	sourcePortSet := make(map[string]bool)
	var eventDate *time.Time

	lines := strings.Split(body, "\n")
	for i, line := range lines {
		dateMatch := datePattern.FindString(line)
		if dateMatch != "" {
			// Parse the date from the log line
			// Extract month, day, and time from the log
			parsedDate := parseDateFromLog(dateMatch, *headerDate)
			eventDate = parsedDate

			// Now look for IP and port information in subsequent lines
			for j := i; j < len(lines); j++ {
				if strings.TrimSpace(lines[j]) == "" {
					break
				}
				ipPortMatches := ipPattern.FindAllStringSubmatch(lines[j], -1)
				if len(ipPortMatches) == 0 {
					break
				}
				// First match is source, second is target
				if len(ipPortMatches) >= 2 {
					targetIP = ipPortMatches[1][1]
					targetPort = ipPortMatches[1][2]
					sourcePortSet[ipPortMatches[0][2]] = true
				}
			}
			break
		}
	}

	// Extract source IP from subject
	sourceIP := common.ExtractOneIP(subject)
	if sourceIP == "" {
		return nil, fmt.Errorf("no source IP found in subject")
	}

	// Create an event for each source port
	var eventList []*events.Event
	for sourcePort := range sourcePortSet {
		event := events.NewEvent("vpsnet")
		event.IP = sourceIP
		event.EventDate = eventDate

		// Convert source port to int
		if portInt, err := strconv.Atoi(sourcePort); err == nil {
			event.Port = portInt
		}

		// Add target information
		if targetIP != "" {
			event.AddEventDetail(&events.Target{
				IP:   targetIP,
				Port: targetPort,
			})
		}

		event.EventTypes = []events.EventType{events.NewPortScan()}
		eventList = append(eventList, event)
	}

	if len(eventList) == 0 {
		return nil, fmt.Errorf("no events created")
	}

	return eventList, nil
}

// parseDateFromLog parses a date string from a log line and combines it with header date info
// The log format is like "Aug 10 14:23:31" and we need to use the year and timezone from the header
func parseDateFromLog(logDate string, headerDate time.Time) *time.Time {
	// Parse the log date parts
	parts := strings.Fields(logDate)
	if len(parts) < 3 {
		return nil
	}

	month := parts[0]
	day := parts[1]
	timeStr := parts[2]

	// Construct a full date string using the year and timezone from header
	year := headerDate.Year()
	zoneName, _ := headerDate.Zone()

	// Format: "Aug 10 2025 14:23:31 UTC"
	fullDateStr := fmt.Sprintf("%s %s %d %s %s", month, day, year, timeStr, zoneName)

	// Try parsing with timezone name
	layouts := []string{
		"Jan 2 2006 15:04:05 MST",
		"Jan 02 2006 15:04:05 MST",
		"Jan 2 2006 15:04:05",
		"Jan 02 2006 15:04:05",
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, fullDateStr); err == nil {
			return &t
		}
	}

	// If parsing with zone name fails, use the header's location
	fullDateStrNoZone := fmt.Sprintf("%s %s %d %s", month, day, year, timeStr)
	for _, layout := range []string{"Jan 2 2006 15:04:05", "Jan 02 2006 15:04:05"} {
		if t, err := time.ParseInLocation(layout, fullDateStrNoZone, headerDate.Location()); err == nil {
			return &t
		}
	}

	return nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
