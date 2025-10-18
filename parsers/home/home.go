package home

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	// IP_PATTERN matches IP addresses in spam termination requests
	ipPattern = regexp.MustCompile(`(?i)(Please (stop( the)? spamming from|terminate|stop) ip ?(&#160;)?)(\[?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\]?)`)

	// IP_PATTERN_2 matches IP addresses in ownership context
	ipPattern2 = regexp.MustCompile(`(?i)((owner of|registrant from) ip ?)(\[?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\]?)`)

	// receivedPattern matches Received headers with IP addresses
	receivedPattern = regexp.MustCompile(`(?i)(Received:.*\s*(\[|\().*\[?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\]?(\]|\)))`)
)

// New creates a new Parser instance (for Bento registration)
func New(serializedEmail email.SerializedEmail, fromAddr, fromName, contentType string) *Parser {
	return &Parser{}
}

func NewParser() *Parser {
	return &Parser{}
}

// parseReceivedHeaders extracts IP addresses from Received headers
func parseReceivedHeaders(body string, eventTemplate *events.Event) ([]*events.Event, error) {
	// Find all matches
	matches := receivedPattern.FindAllStringSubmatch(body, -1)

	if len(matches) <= 1 {
		return nil, common.NewParserError("Unable to find valid IP in the Received: headers")
	}

	// Get the first IP
	var firstIP string
	if len(matches[0]) > 1 {
		firstIP = matches[0][1]
	}

	// Process the last 2 matches
	var results []*events.Event
	var allIPs []string
	startIdx := len(matches) - 2
	if startIdx < 0 {
		startIdx = 0
	}

	for _, match := range matches[startIdx:] {
		if len(match) > 1 {
			ipCandidate := match[1]

			// Skip localhost, duplicates, and first IP
			if strings.Contains(ipCandidate, "127.0.0.1") {
				continue
			}
			if ipCandidate == firstIP {
				continue
			}

			// Check if already seen
			duplicate := false
			for _, seenIP := range allIPs {
				if ipCandidate == seenIP {
					duplicate = true
					break
				}
			}
			if duplicate {
				continue
			}

			allIPs = append(allIPs, ipCandidate)

			// Clean and validate IP
			cleanedIP := common.IsIP(ipCandidate)
			if cleanedIP != "" {
				event := *eventTemplate
				event.IP = cleanedIP
				results = append(results, &event)
			}
		}
	}

	if len(results) > 0 {
		return results, nil
	}

	return nil, common.NewParserError("Unable to find valid IP in the Received: headers")
}

// parseSpam handles spam-related emails
func parseSpam(body string, eventTemplate *events.Event, dateFallback string) ([]*events.Event, error) {
	// Set event date from fallback
	if dateFallback != "" {
		eventTemplate.EventDate = email.ParseDate(dateFallback)
	}

	eventTemplate.EventTypes = []events.EventType{events.NewSpam()}

	// Try first IP pattern
	if match := ipPattern.FindStringSubmatch(body); match != nil && len(match) > 5 {
		cleanedIP := common.IsIP(match[5])
		if cleanedIP != "" {
			eventTemplate.IP = cleanedIP
			return []*events.Event{eventTemplate}, nil
		}
	}

	// Try second IP pattern
	if match := ipPattern2.FindStringSubmatch(body); match != nil && len(match) > 3 {
		cleanedIP := common.IsIP(match[3])
		if cleanedIP != "" {
			eventTemplate.IP = cleanedIP
			return []*events.Event{eventTemplate}, nil
		}
	}

	// Try to find X-SourceIP header
	ip := common.FindStringWithoutMarkers(strings.ToLower(body), "x-sourceip:", "")
	if ip != "" {
		cleanedIP := common.IsIP(ip)
		if cleanedIP != "" {
			eventTemplate.IP = cleanedIP
			return []*events.Event{eventTemplate}, nil
		}
	}

	// If no IP found, try to parse from Received headers
	if eventTemplate.IP == "" {
		return parseReceivedHeaders(body, eventTemplate)
	}

	return []*events.Event{eventTemplate}, nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, _ := common.GetSubject(serializedEmail, false)

	event := events.NewEvent("home")

	// Check if this is a spam or advertising complaint
	bodyLower := strings.ToLower(body)
	if strings.Contains(bodyLower, "spam") || strings.Contains(bodyLower, "advertising") {
		// Get date from headers
		var dateFallback string
		if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
			dateFallback = dateHeader[0]
		}

		return parseSpam(body, event, dateFallback)
	}

	// If not spam/advertising, this is an unknown type
	return nil, common.NewNewTypeError(subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
