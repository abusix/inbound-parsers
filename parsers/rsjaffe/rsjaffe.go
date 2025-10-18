// Package rsjaffe implements the rsjaffe@gmail.com parser
package rsjaffe

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the rsjaffe parser
type Parser struct{}

var (
	dataPattern = regexp.MustCompile(`(?P<date>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*SRC=(?P<ip>.+) DST=(?P<dst>.*?) .*(?:SPT=(?P<src_port>\d+) DPT=(?P<dst_port>\d+))`)
)

// Parse parses emails from rsjaffe@gmail.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Extract timezone
	timezone := common.FindStringWithoutMarkers(body, "UTC", ".")
	if timezone == "" {
		timezone = "UTC"
	}

	// Get header date for year calculation
	var headerDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		headerDate = email.ParseDate(dateHeaders[0])
	}
	if headerDate == nil {
		now := time.Now()
		headerDate = &now
	}

	// Find all matches
	matches := dataPattern.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return nil, common.NewParserError("Could not find data")
	}

	var eventList []*events.Event

	for _, match := range matches {
		// Extract named groups
		dateStr := match[1]  // date
		ip := match[2]       // ip
		dst := match[3]      // dst
		srcPort := match[4]  // src_port
		dstPort := match[5]  // dst_port

		event := events.NewEvent("rsjaffe")
		event.EventTypes = []events.EventType{events.NewExploit()}

		// Parse date: split into month, day, time
		dateParts := strings.Fields(dateStr)
		if len(dateParts) < 3 {
			continue
		}
		month := dateParts[0]
		day := dateParts[1]
		timeStr := dateParts[2]

		// Get most plausible date
		eventDate := getMostPlausibleDate(headerDate, month, day, timeStr, timezone)
		event.EventDate = eventDate

		// Set port (from src_port)
		if port, err := strconv.Atoi(srcPort); err == nil {
			event.Port = port
		}

		// Set IP
		event.IP = strings.TrimSpace(ip)

		// Add Target detail
		target := &events.Target{
			IP:   strings.TrimSpace(dst),
			Port: strings.TrimSpace(dstPort),
		}
		event.AddEventDetail(target)

		eventList = append(eventList, event)
	}

	return eventList, nil
}

// getMostPlausibleDate determines the most likely year for a syslog date
// (which only has month, day, time but no year)
func getMostPlausibleDate(headerDate *time.Time, month, day, timeStr, timezone string) *time.Time {
	year := headerDate.Year()

	// Try this year
	dateThisYear := parseDateWithYear(day, month, year, timeStr, timezone)
	if dateThisYear == nil {
		// Try last year as fallback
		return parseDateWithYear(day, month, year-1, timeStr, timezone)
	}

	// If this year's date is in the future compared to header date, use last year
	if dateThisYear.After(*headerDate) {
		return parseDateWithYear(day, month, year-1, timeStr, timezone)
	}

	return dateThisYear
}

// parseDateWithYear constructs a date from components and parses it
func parseDateWithYear(day, month string, year int, timeStr, timezone string) *time.Time {
	// Construct date string: "2 Jan 2024 12:34:56 UTC"
	dateString := fmt.Sprintf("%s %s %d %s %s", day, month, year, timeStr, timezone)
	parsed := email.ParseDate(dateString)
	return parsed
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
