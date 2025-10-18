package hetzner

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/parsers/spamcop"
	email "github.com/abusix/inbound-parsers/pkg/email"
)

// Regular expressions for date matching in netscan events
var (
	// DATE_MATCHER: Matches format like "Jan 15 15:30:45 2025 TCP 1.2.3.4 12345 => 5.6.7.8 80"
	dateMatcher = regexp.MustCompile(
		`(?i)>?\s*(?P<time>.*?)\s+(?P<year>\d{4})\s+(?P<protocol>TCP|UDP)\s+` +
			`(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(?P<src_port>\d+)\s+=>\s+` +
			`(?P<dest_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(?P<dest_port>\d+)`,
	)

	// DATE_MATCHER_2: Matches format like "2025-01-15 15:30:45 1.2.3.4 12345 -> 5.6.7.8 80 123 TCP"
	dateMatcher2 = regexp.MustCompile(
		`>\s+(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+` +
			`(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(?P<src_port>\d+)\s+->\s+` +
			`(?P<dest_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(?P<dest_port>\d+)\s+\d+\s+` +
			`(?P<protocol>TCP|UDP)`,
	)
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, _ := common.GetSubject(serializedEmail, false)
	body, _ := common.GetBody(serializedEmail, false)

	var result []*events.Event
	subjectLower := strings.ToLower(subject)

	// Check if this is a spamcop report
	if checkSpamcop(body, subject) {
		// Call spamcop parser
		spamcopParser := spamcop.NewParser()
		events, err := spamcopParser.Parse(serializedEmail)
		if err != nil {
			return nil, err
		}
		// Update parser name to hetzner
		for _, event := range events {
			event.Parser = "hetzner"
		}
		return events, nil
	}

	if body != "" {
		if strings.Contains(subjectLower, "attackinlevel") {
			result = parseAttack(serializedEmail, body, subject)
		} else if strings.Contains(subjectLower, "netscaninlevel") ||
			strings.Contains(subjectLower, "portscaninlevel") ||
			strings.Contains(subjectLower, "netscanoutlevel") {
			result = parseNetscan(serializedEmail, body, subject)
		} else {
			return nil, fmt.Errorf("unknown hetzner email type: %s", subject)
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no events created")
	}

	return result, nil
}

// checkSpamcop checks if the email is a spamcop report
func checkSpamcop(body, subject string) bool {
	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)
	return strings.Contains(bodyLower, "spamcop") || strings.Contains(subjectLower, "spamcop")
}

// parseAttack parses attack-type emails
func parseAttack(serializedEmail *email.SerializedEmail, body, subject string) []*events.Event {
	var result []*events.Event
	targetIPSet := make(map[string]bool)

	// Parse lines starting with "> External "
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "> External ") {
			// Remove the prefix
			line = strings.TrimPrefix(line, "> External ")
			// Extract IP before comma
			parts := strings.SplitN(line, ",", 2)
			if len(parts) > 0 {
				targetIP := strings.TrimSpace(parts[0])
				targetIPSet[targetIP] = true
			}
		}
	}

	// Create an event for each unique target IP
	for targetIP := range targetIPSet {
		event := events.NewEvent("hetzner")
		event.EventTypes = []events.EventType{events.NewPortScan()}
		event.IP = subject // Source IP is in the subject

		// Parse event date from headers
		if headers := serializedEmail.Headers; headers != nil {
			if dateHeaders, ok := headers["date"]; ok && len(dateHeaders) > 0 {
				eventDate := email.ParseDate(dateHeaders[0])
				event.EventDate = eventDate
			}
		}

		// Add target IP
		event.AddEventDetail(&events.Target{
			IP: targetIP,
		})

		result = append(result, event)
	}

	return result
}

// parseNetscan parses netscan/portscan emails
func parseNetscan(serializedEmail *email.SerializedEmail, body, subject string) []*events.Event {
	var result []*events.Event

	// Try to extract IP from subject
	subjectIP := common.ExtractOneIP(subject)

	// First pattern: time + year format
	matches := dateMatcher.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) < 8 {
			continue
		}

		// Extract named groups (indices based on regex structure)
		// Groups: 0=full match, 1=time, 2=year, 3=protocol, 4=src_ip, 5=src_port, 6=dest_ip, 7=dest_port
		timeStr := match[1]
		year := match[2]
		protocol := match[3]
		srcIP := match[4]
		srcPort := match[5]
		destIP := match[6]
		destPort := match[7]

		event := events.NewEvent("hetzner")
		event.EventTypes = []events.EventType{events.NewPortScan()}

		// Parse date: "time CET year"
		dateStr := timeStr + " CET " + year
		eventDate := email.ParseDate(dateStr)
		event.EventDate = eventDate

		// Set source IP
		if subjectIP != "" {
			event.IP = subjectIP
		} else {
			event.IP = srcIP
		}

		// Set source port
		if port, err := strconv.Atoi(srcPort); err == nil {
			event.Port = port
		}

		// Add target details
		event.AddEventDetail(&events.Target{
			IP:   destIP,
			Port: destPort,
		})

		// Add transport protocol
		event.AddEventDetail(&events.TransportProtocol{
			Protocol: protocol,
		})

		result = append(result, event)
	}

	// Second pattern: ISO date format
	matches2 := dateMatcher2.FindAllStringSubmatch(body, -1)
	for _, match := range matches2 {
		if len(match) < 7 {
			continue
		}

		// Groups: 0=full match, 1=date, 2=src_ip, 3=src_port, 4=dest_ip, 5=dest_port, 6=protocol
		dateStr := match[1]
		srcIP := match[2]
		srcPort := match[3]
		destIP := match[4]
		destPort := match[5]
		protocol := match[6]

		event := events.NewEvent("hetzner")
		event.EventTypes = []events.EventType{events.NewPortScan()}

		// Parse date
		eventDate := email.ParseDate(dateStr)
		event.EventDate = eventDate

		// Set source IP
		event.IP = srcIP

		// Set source port
		if port, err := strconv.Atoi(srcPort); err == nil {
			event.Port = port
		}

		// Add target details
		event.AddEventDetail(&events.Target{
			IP:   destIP,
			Port: destPort,
		})

		// Add transport protocol
		event.AddEventDetail(&events.TransportProtocol{
			Protocol: protocol,
		})

		result = append(result, event)
	}

	return result
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
