// Package hyperfilter implements the Hyperfilter parser for abuse reports
package hyperfilter

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the Hyperfilter parser
type Parser struct{}

var (
	// Date pattern 1: MM/DD/YYYY HH:MM:SS +/-NNNN TZ
	betterDatePattern1 = regexp.MustCompile(
		`(?P<month>\d{1,2})[/](?P<day>\d{1,2})[/](?P<year>\d{4})\s+` +
			`(?P<time>[0-9:]{8})\s(?P<tzd>[0-9:-]{5,6})\s(?P<tz>\w{3})`,
	)

	// Date pattern 2: YYYY/MM/DD HH:MM:SS
	betterDatePattern2 = regexp.MustCompile(
		`(?P<year>\d{4})[\/](?P<month>\d{1,2})[\/](?P<day>\d{1,2})\s+(?P<time>[0-9:]{8})`,
	)

	// IP pattern: srcIP:srcPort -> dstIP:dstPort
	ipPattern = regexp.MustCompile(
		`(?P<src_ip>\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}):(?P<src_port>\d+)\s*(->)?\s*` +
			`(?P<dst_ip>\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}):(?P<dst_port>\d+)`,
	)
)

// ipPair represents a unique source IP and destination IP combination
type ipPair struct {
	srcIP string
	dstIP string
}

// Parse parses emails from abuse@hyperfilter.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	var eventsList []*events.Event

	if body != "" {
		// Track unique IP pairs to avoid duplicates
		seenIPPairs := make(map[ipPair]bool)

		// Process each line in the body
		for _, line := range strings.Split(body, "\n") {
			// Try to match date patterns
			var dateMatch []string
			var dateGroups map[string]string
			var datePattern *regexp.Regexp

			// Try first date pattern
			if matches := betterDatePattern1.FindStringSubmatch(line); matches != nil {
				dateMatch = matches
				dateGroups = extractGroups(betterDatePattern1, matches)
				datePattern = betterDatePattern1
			} else if matches := betterDatePattern2.FindStringSubmatch(line); matches != nil {
				// Try second date pattern
				dateMatch = matches
				dateGroups = extractGroups(betterDatePattern2, matches)
				datePattern = betterDatePattern2
			}

			// If we found a date, try to find IP information on the same line
			if dateMatch != nil {
				if ipMatches := ipPattern.FindStringSubmatch(line); ipMatches != nil {
					ipGroups := extractGroups(ipPattern, ipMatches)

					// Clean IP addresses (remove brackets)
					srcIP := common.IsIP(ipGroups["src_ip"])
					dstIP := common.IsIP(ipGroups["dst_ip"])

					if srcIP == "" || dstIP == "" {
						continue
					}

					// Check if we've already seen this IP pair
					pair := ipPair{srcIP: srcIP, dstIP: dstIP}
					if seenIPPairs[pair] {
						continue
					}
					seenIPPairs[pair] = true

					// Create event
					event := events.NewEvent("hyperfilter")
					event.EventTypes = []events.EventType{events.NewPortScan()}

					// Set source IP and port
					event.IP = srcIP
					if port, err := common.ParsePort(ipGroups["src_port"]); err == nil {
						event.Port = port
					}

					// Add target (destination) information
					target := &events.Target{
						IP:   dstIP,
						Port: ipGroups["dst_port"],
					}
					event.AddEventDetail(target)

					// Format and set event date
					var reformattedDate string
					if datePattern == betterDatePattern1 {
						// Format: DD/MM/YYYY HH:MM:SS +/-NNNN
						reformattedDate = fmt.Sprintf("%s/%s/%s %s %s",
							dateGroups["day"],
							dateGroups["month"],
							dateGroups["year"],
							dateGroups["time"],
							dateGroups["tzd"],
						)
					} else {
						// Format: DD/MM/YYYY HH:MM:SS
						reformattedDate = fmt.Sprintf("%s/%s/%s %s",
							dateGroups["day"],
							dateGroups["month"],
							dateGroups["year"],
							dateGroups["time"],
						)
					}

					// Parse the reformatted date
					event.EventDate = parseHyperfilterDate(reformattedDate)

					eventsList = append(eventsList, event)
				}
			}
		}
	} else {
		// No body - check subject for "Intrusion Detected"
		if serializedEmail.Headers != nil {
			if subjects, ok := serializedEmail.Headers["subject"]; ok && len(subjects) > 0 {
				subject := subjects[0]

				if strings.Contains(subject, "Intrusion Detected") {
					event := events.NewEvent("hyperfilter")
					event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
					event.IP = subject // Python sets IP to the whole subject

					// Set event date from email date header
					if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
						event.EventDate = email.ParseDate(dates[0])
					}

					eventsList = append(eventsList, event)
				}
			}
		}
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no events created")
	}

	return eventsList, nil
}

// extractGroups extracts named groups from regex matches
func extractGroups(pattern *regexp.Regexp, matches []string) map[string]string {
	result := make(map[string]string)
	names := pattern.SubexpNames()

	for i, name := range names {
		if i > 0 && i < len(matches) {
			result[name] = matches[i]
		}
	}

	return result
}

// parseHyperfilterDate parses dates in Hyperfilter format
// Format 1: "DD/MM/YYYY HH:MM:SS +/-NNNN"
// Format 2: "DD/MM/YYYY HH:MM:SS"
func parseHyperfilterDate(dateStr string) *time.Time {
	if dateStr == "" {
		return nil
	}

	// Try with timezone offset first
	formats := []string{
		"02/01/2006 15:04:05 -0700",  // DD/MM/YYYY HH:MM:SS +/-NNNN
		"02/01/2006 15:04:05",         // DD/MM/YYYY HH:MM:SS
		"2/1/2006 15:04:05 -0700",     // D/M/YYYY HH:MM:SS +/-NNNN
		"2/1/2006 15:04:05",           // D/M/YYYY HH:MM:SS
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return &t
		}
	}

	return nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
