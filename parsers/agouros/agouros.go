// Package agouros implements the agouros.de parser for login attacks
package agouros

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the agouros parser
type Parser struct{}

var (
	datePattern = regexp.MustCompile(`\d{2}.\d{2}.\d{4}`)
)

// Parse parses emails from abuse-out@agouros.de
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	var eventsList []*events.Event
	sourceIPs := make(map[string]bool)
	timeZone := ""

	lines := strings.Split(body, "\n")
	for _, line := range lines {
		// Check for timezone information
		if strings.HasPrefix(line, "The times included") {
			if strings.HasSuffix(line, "Central European (Summer) Time.") {
				timeZone = "CEST"
			} else if strings.HasSuffix(line, "Central European Time (CET).") {
				timeZone = "CET"
			} else {
				// Unknown timezone - return empty events like Python version
				return nil, common.NewParserError("unknown timezone in agouros")
			}
			continue
		}

		// Check if line starts with date pattern
		if !datePattern.MatchString(line) {
			continue
		}

		// Parse the tab-separated line using rpartition logic from Python
		// Python logic:
		// date_srcip_and_port, _, target_ip = line.rpartition('\t')
		// date_and_srcip, _, port = date_srcip_and_port.rpartition('\t')
		// date_info, _, srcip = date_and_srcip.rpartition('\t')

		// First rpartition: split on last tab to get target_ip
		dateSrcIPAndPort, targetIP := rpartition(line, "\t")
		dateSrcIPAndPort = strings.Trim(dateSrcIPAndPort, " \t")

		// Second rpartition: split on last tab to get port
		dateAndSrcIP, port := rpartition(dateSrcIPAndPort, "\t")
		dateAndSrcIP = strings.Trim(dateAndSrcIP, " \t")

		// Third rpartition: split on last tab to get srcip
		dateInfo, srcIP := rpartition(dateAndSrcIP, "\t")

		// Build date string
		var dateStr string
		dateInfoParts := strings.Fields(dateInfo)
		if len(dateInfoParts) < 3 {
			dateStr = fmt.Sprintf("%s %s", dateInfo, timeZone)
		} else {
			dateStr = dateInfo
		}

		// Skip if we've already seen this source IP
		if sourceIPs[srcIP] {
			continue
		}
		sourceIPs[srcIP] = true

		// Create event
		event := events.NewEvent("agouros")

		// Set IP
		ip := common.ExtractOneIP(srcIP)
		if validIP := common.IsIP(ip); validIP != "" {
			event.IP = validIP
		}

		// Set date
		eventDate := email.ParseDate(dateStr)
		event.EventDate = eventDate

		// Set port
		event.Port = parsePort(port)

		// Set event type
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

		// Add target
		if targetIP != "" {
			event.AddEventDetail(&events.Target{IP: targetIP})
		}

		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return eventsList, nil
}

// rpartition splits the string at the last occurrence of sep
// Returns (before, after) like Python's rpartition but without the separator
func rpartition(s, sep string) (string, string) {
	idx := strings.LastIndex(s, sep)
	if idx == -1 {
		return s, ""
	}
	return s[:idx], s[idx+len(sep):]
}

func parsePort(portStr string) int {
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return port
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
