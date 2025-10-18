// Package serviceexpress implements the ServiceExpress parser for exploit reports
package serviceexpress

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the ServiceExpress parser
type Parser struct{}

// Parse parses emails from @serviceexpress
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get email body
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	body = strings.ToLower(body)

	// Check if email contains 'exploit'
	if !strings.Contains(body, "exploit") {
		return nil, common.NewNewTypeError("adapt the parser")
	}

	// Extract IPs from line after 'following ip address'
	ipLine := common.GetNonEmptyLineAfter(body, "following ip address")
	if ipLine == "" {
		return nil, common.NewParserError("no IP line found after 'following ip address'")
	}

	// Find all IPs in the line (pattern: digits and dots)
	ipPattern := regexp.MustCompile(`[\d\.]+`)
	ips := ipPattern.FindAllString(ipLine, -1)

	if len(ips) == 0 {
		return nil, common.NewParserError("no IPs found in IP line")
	}

	// Extract date string between 'attack was on' and 'to'
	dateString := common.FindStringWithoutMarkers(body, "attack was on", "to")
	dateString = strings.TrimSpace(dateString)
	dateString = strings.Replace(dateString, " from", "", -1)

	// Parse the date components
	// Example: "September 13th 12:08:05 CST"
	dateString = strings.Replace(dateString, "  ", " ", -1)
	parts := strings.Split(dateString, " ")

	if len(parts) != 4 {
		return nil, common.NewParserError(fmt.Sprintf("unexpected date format: %s", dateString))
	}

	month := parts[0]
	day := parts[1]
	timeStr := parts[2]
	zone := parts[3]

	// Get year from email date header
	var year int
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		emailDate := email.ParseDate(dateHeaders[0])
		if emailDate != nil {
			year = emailDate.Year()
		}
	}
	if year == 0 {
		year = time.Now().Year()
	}

	// Clean up month (take first 3 chars)
	if len(month) > 3 {
		month = month[:3]
	}

	// Clean up day (remove ordinal suffix like 'th', 'st', 'rd', 'nd')
	day = regexp.MustCompile(`[a-z]+`).ReplaceAllString(day, "")
	// Pad day with zero
	if len(day) == 1 {
		day = "0" + day
	}

	// Pad time to 8 chars (HH:MM:SS)
	for len(timeStr) < 8 {
		timeStr = "0" + timeStr
	}

	// Construct date string
	dateStr := fmt.Sprintf("%d %s %s %s %s", year, month, day, timeStr, strings.ToUpper(zone))

	// Parse the constructed date
	eventDate := email.ParseDate(dateStr)

	// Create events for each IP
	var eventsList []*events.Event

	for _, ip := range ips {
		// Validate IP
		validIP := common.IsIP(ip)
		if validIP == "" {
			continue
		}

		event := events.NewEvent("serviceexpress")
		event.EventTypes = []events.EventType{events.NewExploit()}
		event.EventDate = eventDate
		event.IP = validIP

		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
