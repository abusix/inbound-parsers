// Package serverstack implements the serverstack parser
package serverstack

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/parsers/espresso"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the serverstack parser
type Parser struct{}

// NewParser creates a new serverstack parser
func NewParser() *Parser {
	return &Parser{}
}

// createSimpleEvent creates a simple event with the given event type
func createSimpleEvent(eventType events.EventType) []*events.Event {
	event := events.NewEvent("serverstack")
	event.EventTypes = []events.EventType{eventType}
	return []*events.Event{event}
}

// parseBruteForce parses brute force attack logs
func parseBruteForce(body, dateStr string, externalCaseInfo *events.ExternalCaseInformation) ([]*events.Event, error) {
	date := email.ParseDate(dateStr)
	if date == nil {
		return nil, common.NewParserError("failed to parse date")
	}
	year := date.Year()

	var result []*events.Event
	ipPortCombinations := make(map[string]bool)

	// Regex to match: (.*)SRC=(.*)DST=(.*)PROTO=(.*)SPT=(.*)DPT=(.*)
	regex := regexp.MustCompile(`(.*)SRC=(.*)DST=(.*)PROTO=(.*)SPT=(.*)DPT=(.*)`)

	for _, line := range common.GetBlockAround(body, "SRC=") {
		matches := regex.FindStringSubmatch(line)
		if len(matches) >= 7 {
			dateField := strings.TrimSpace(matches[1])
			srcIP := strings.TrimSpace(matches[2])
			dstIP := strings.TrimSpace(matches[3])
			proto := strings.TrimSpace(matches[4])
			srcPort := strings.TrimSpace(matches[5])
			dstPort := strings.TrimSpace(matches[6])

			ipPortCombination := fmt.Sprintf("%s:%s-%s:%s", srcIP, srcPort, dstIP, dstPort)
			if ipPortCombinations[ipPortCombination] {
				continue
			}
			ipPortCombinations[ipPortCombination] = true

			// Parse date: "Month Day Time"
			parts := strings.Fields(dateField)
			if len(parts) >= 3 {
				month := parts[0]
				day := parts[1]
				timeStr := parts[2]
				fullDateStr := fmt.Sprintf("%s %s %d %s", month, day, year, timeStr)

				event := events.NewEvent("serverstack")
				event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
				event.EventDate = email.ParseDate(fullDateStr)
				event.IP = srcIP

				// Parse source port
				if port, err := strconv.Atoi(srcPort); err == nil {
					event.Port = port
				}

				// Add target
				event.AddEventDetail(&events.Target{
					IP:   dstIP,
					Port: dstPort,
				})

				// Add transport protocol
				event.AddEventDetail(&events.TransportProtocol{
					Protocol: proto,
				})

				result = append(result, event)
			}
		}
	}

	if len(result) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return result, nil
}

// Parse parses emails from @serverstack
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)
	bodyLower := strings.ToLower(body)

	// Extract date - prefer "Most recent" date from body
	var date string
	mostRecentDate := common.FindStringWithoutMarkers(body, "Most recent", "")
	if mostRecentDate != "" {
		parsedDate := email.ParseDate(mostRecentDate)
		if parsedDate != nil {
			date = mostRecentDate
		}
	}

	// Fall back to email header date
	if date == "" {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			date = dateHeaders[0]
		}
	}

	// Extract external case information
	status := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Status:", ""))
	priority := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Priority:", ""))
	ticketID := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Ticket ID:", ""))

	externalCaseInfo := &events.ExternalCaseInformation{
		Status:   status,
		Severity: priority,
		CaseID:   ticketID,
	}

	var result []*events.Event
	var url string

	// Determine event type based on subject/body
	if strings.Contains(subjectLower, "rbl") {
		// Parse using espresso parser
		espressoParser := espresso.Parser{}
		espressoEvents, err := espressoParser.Parse(serializedEmail)
		if err != nil {
			return nil, err
		}
		// Update parser name
		for _, event := range espressoEvents {
			event.Parser = "serverstack"
		}
		result = espressoEvents

	} else if strings.Contains(subjectLower, "phishing") {
		result = createSimpleEvent(events.NewPhishing())

	} else if strings.Contains(subjectLower, "spam") {
		result = createSimpleEvent(events.NewSpam())

	} else if strings.Contains(subjectLower, "netscan") ||
		strings.Contains(subjectLower, "malicious activity") ||
		strings.Contains(subjectLower, "masscan") ||
		strings.Contains(subjectLower, "portscan") {
		result = createSimpleEvent(events.NewPortScan())

	} else if strings.Contains(subjectLower, "attack source") {
		result = createSimpleEvent(events.NewBot(""))

	} else if (strings.Contains(subjectLower, "attacked") && strings.Contains(bodyLower, "syn")) ||
		strings.Contains(subjectLower, "unwelcome network traffic") {
		result = createSimpleEvent(events.NewDDoS())

	} else if strings.Contains(subjectLower, "infringing") {
		result = createSimpleEvent(events.NewTrademark("", nil, "", ""))

	} else if strings.Contains(subjectLower, "ssh") ||
		strings.Contains(body, "ssh") ||
		strings.Contains(subjectLower, "loginattempt") {
		result = createSimpleEvent(events.NewLoginAttack("", ""))

	} else if strings.Contains(bodyLower, "copyright infringement") {
		owner := strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "content owner:", ""))

		// Try to find pageurl
		if strings.Contains(bodyLower, "pageurl") {
			url = strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "pageurl:", ""))
			if url == "" {
				url = strings.TrimSpace(common.GetNonEmptyLineAfter(bodyLower, "pageurl"))
			}
		}

		result = createSimpleEvent(events.NewCopyright("", owner, ""))

	} else if strings.Contains(bodyLower, "malware") {
		result = createSimpleEvent(events.NewMalware(""))

	} else if strings.Contains(bodyLower, "brute force") {
		return parseBruteForce(body, date, externalCaseInfo)

	} else if strings.Contains(subjectLower, "scam") ||
		strings.Contains(subjectLower, "fraud") ||
		strings.Contains(body, "fraud") {
		result = createSimpleEvent(events.NewFraud())

	} else {
		return nil, common.NewNewTypeError(subjectLower)
	}

	// Extract URL from hxxp pattern if not already set
	if strings.Contains(bodyLower, "hxxp") && url == "" {
		hxxpPart := common.FindStringWithoutMarkers(bodyLower, "hxxp", "")
		if hxxpPart != "" {
			url = "http" + hxxpPart
		}
	}

	// Post-process all events
	for _, event := range result {
		event.URL = url
		event.AddEventDetail(externalCaseInfo)
		event.EventDate = email.ParseDate(date)

		// Extract IP from subject if not set
		if event.IP == "" {
			cleanSubject := strings.ReplaceAll(subjectLower, "[.]", ".")
			event.IP = common.ExtractOneIP(cleanSubject)
		}

		// Extract IP from "regarding" field if still not set
		if event.IP == "" {
			regarding := common.FindStringWithoutMarkers(body, "regarding", "")
			cleanRegarding := strings.ReplaceAll(regarding, "[.]", ".")
			event.IP = common.ExtractOneIP(cleanRegarding)
		}
	}

	if len(result) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
