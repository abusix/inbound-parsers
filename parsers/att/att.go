package att

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// IP_PATTERN matches spammer IP in the body
// Pattern: (spammer|spam) : http://xxx.xxx.xxx.xxx
// Note: dots are not escaped to match Python behavior (. matches any char)
var ipPattern = regexp.MustCompile(`(?i)((spammer|spam)\s*(:|-)\s*)\s*http://(?P<spammer_ip>\d{2,3}.\d{2,3}.\d{2,3}.\d{2,3})`)

// originatingIPPattern matches X-Originating-IP headers in body
var originatingIPPattern = regexp.MustCompile(`(?i)(X-Originating-IP:\s*)\s*\[?(?P<ip>\d{2,3}\.\d{2,3}\.\d{2,3}\.\d{2,3})\]?`)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)

	event := events.NewEvent("att")

	// Get date from email headers
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Check if body contains "spammer" keyword
	bodyLower := strings.ToLower(body)
	if strings.Contains(bodyLower, "spammer") {
		return parseSpam(body, event)
	}

	return parseReceivedHeaders(body, event)
}

// parseSpam extracts IP from spammer URL pattern
func parseSpam(body string, event *events.Event) ([]*events.Event, error) {
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Try to find IP in spammer URL pattern
	if match := ipPattern.FindStringSubmatch(body); match != nil {
		// Find the named group index for "spammer_ip"
		for i, name := range ipPattern.SubexpNames() {
			if name == "spammer_ip" && i < len(match) {
				ip := strings.ReplaceAll(match[i], "[.]", ".")
				ip = strings.TrimSpace(ip)
				event.IP = ip
				break
			}
		}
	}

	// If we found an IP, return the event
	if event.IP != "" {
		return []*events.Event{event}, nil
	}

	// Otherwise fall back to parsing received headers
	return parseReceivedHeaders(body, event)
}

// parseReceivedHeaders extracts IP from X-Originating-IP headers
func parseReceivedHeaders(body string, event *events.Event) ([]*events.Event, error) {
	var ips []string

	// Find all X-Originating-IP matches
	matches := originatingIPPattern.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		// Find the named group index for "ip"
		for i, name := range originatingIPPattern.SubexpNames() {
			if name == "ip" && i < len(match) {
				ip := match[i]
				ips = append(ips, ip)
				break
			}
		}
	}

	// If we found IPs, use the last one
	if len(ips) > 0 {
		event.EventTypes = []events.EventType{events.NewSpam()}
		event.IP = ips[len(ips)-1]
		return []*events.Event{event}, nil
	}

	// No IPs found - return empty list
	return []*events.Event{}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
