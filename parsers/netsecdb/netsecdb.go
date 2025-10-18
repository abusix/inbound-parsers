package netsecdb

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// eventTypeMapping maps keywords to event type constructors and validation requirements
type eventTypeMapping struct {
	eventTypeCtor  func() events.EventType
	requiredMarker string
	hintMarkers    []string
}

var mapping = map[string]eventTypeMapping{
	"NETSECDB_SPAM":                {eventTypeCtor: func() events.EventType { return events.NewSpam() }, requiredMarker: "", hintMarkers: []string{"[qsheff] spam"}},
	"NETSECDB_SPAM_BLACKMAIL":      {eventTypeCtor: func() events.EventType { return events.NewSpam() }, requiredMarker: "", hintMarkers: []string{"[qsheff] spam"}},
	"NETSECDB_SPAM_PHISHING":       {eventTypeCtor: func() events.EventType { return events.NewPhishing() }, requiredMarker: "", hintMarkers: nil},
	"NETSECDB_HACKING_DNS":         {eventTypeCtor: func() events.EventType { return events.NewWebHack() }, requiredMarker: "", hintMarkers: []string{"dns named["}},
	"NETSECDB_HACKING_HTTP":        {eventTypeCtor: func() events.EventType { return events.NewWebHack() }, requiredMarker: "", hintMarkers: nil},
	"NETSECDB_HACKING_HTTP_SMTP":   {eventTypeCtor: func() events.EventType { return events.NewWebHack() }, requiredMarker: "", hintMarkers: nil},
	"NETSECDB_HACKING_SMTP":        {eventTypeCtor: func() events.EventType { return events.NewAuthFailure() }, requiredMarker: "smtp_auth", hintMarkers: []string{"dns "}},
	"NETSECDB_HACKING_IMAP":        {eventTypeCtor: func() events.EventType { return events.NewAuthFailure() }, requiredMarker: "-login", hintMarkers: []string{"dns dovecot"}},
	"NETSECDB_HACKING_EXPLOITURL":  {eventTypeCtor: func() events.EventType { return events.NewExploit() }, requiredMarker: "", hintMarkers: nil},
	"NETSECDB_SPAMMER_HACKING_HTTP": {eventTypeCtor: func() events.EventType { return events.NewPhishing() }, requiredMarker: "blocked by captcha module", hintMarkers: nil},
	"NETSECDB_PORTSCAN_SMTP":       {eventTypeCtor: func() events.EventType { return events.NewPortScan() }, requiredMarker: "", hintMarkers: nil},
}

// eventDateExtractor extracts event date from log lines
func eventDateExtractor(logLine, year string) *time.Time {
	// Pattern 1: dd/mm/yyyy hh:mm:ss (CET timezone)
	if match := regexp.MustCompile(`^(?P<date>([0-9]{2}/){2}[0-9]{4} ([0-9]{2}:){2}[0-9]{2})`).FindStringSubmatch(logLine); match != nil {
		// mail mentions that logfiles are always in CET (+0100)
		eventDateStr := match[0] + "+0100"
		if t, err := time.Parse("02/01/2006 15:04:05-0700", eventDateStr); err == nil {
			return &t
		}
	}

	// Pattern 2: [dd/Mon/yyyy:hh:mm:ss +zzzz]
	if match := regexp.MustCompile(`\[(?P<date>[0-9]{2}/[a-zA-Z]+/[0-9]{4}:([0-9]{2}:){2}[0-9]{2} \+[0-9]{4})]`).FindStringSubmatch(logLine); match != nil {
		eventDateStr := match[1]
		if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", eventDateStr); err == nil {
			return &t
		}
	}

	// Pattern 3: Mon dd hh:mm:ss (requires year)
	if year != "" {
		if match := regexp.MustCompile(`(?P<date>[a-zA-Z]+ [0-9]{1,2} ([0-9]{2}:){2}[0-9]{2})`).FindStringSubmatch(logLine); match != nil {
			dateParts := strings.Fields(match[0])
			if len(dateParts) == 3 {
				// Insert year between day and time
				eventDateStr := fmt.Sprintf("%s %s %s %s +0100", dateParts[0], dateParts[1], year, dateParts[2])
				if t, err := time.Parse("Jan 2 2006 15:04:05 -0700", eventDateStr); err == nil {
					return &t
				}
			}
		}
	}

	return nil
}

// obtainEventInfo extracts event information from the email body
func obtainEventInfo(bodyLower, keyword, requiredMarker string, hintMarkers []string) ([]*events.Event, error) {
	// Pre-process body to ensure proper line breaks after forwarded message marker
	bodyLower = regexp.MustCompile(`(^---- weitergeleitete nachricht.*$)`).ReplaceAllString(bodyLower, "$1\n")

	// Try to extract log lines using the main marker
	logLines, err := common.GetBlockAroundWithContinueUntil(bodyLower, "---- weitergeleitete nachricht", "---- ende")
	if err != nil || len(logLines) == 0 {
		// Try hint markers if main marker didn't work
		if hintMarkers != nil {
			for _, hint := range hintMarkers {
				logLines, err = common.GetBlockAroundWithContinueUntil(bodyLower, hint, "your netsecdb")
				if err == nil && len(logLines) > 0 {
					break
				}
			}
		}
	}

	// Validate required marker if specified
	if requiredMarker != "" {
		found := false
		for _, line := range logLines {
			if strings.Contains(line, requiredMarker) {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("expected marker '%s' not found in log lines", requiredMarker)
		}
	}

	// Extract IPs and event date
	var ips []string
	var eventDate *time.Time
	var year string

	for _, line := range logLines {
		// Replace non-breaking spaces
		line = regexp.MustCompile(`\xa0+`).ReplaceAllString(line, " ")

		// Extract year from datum: line
		if strings.HasPrefix(line, "datum:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				dateParts := strings.Split(parts[1], "-")
				if len(dateParts) > 0 {
					year = dateParts[0]
				}
			}
		}

		// Special case for exploit cases - all IPs could be an event
		if keyword == "NETSECDB_HACKING_EXPLOITURL" {
			ips = append(ips, common.ExtractAllIPv4(line)...)
		} else if len(ips) == 0 {
			if ip := common.ExtractOneIP(line); ip != "" {
				ips = []string{ip}
			}
		}

		// Extract event date
		if eventDate == nil {
			eventDate = eventDateExtractor(line, year)
		}
	}

	// Create events for each IP
	var result []*events.Event
	for _, ip := range ips {
		event := events.NewEvent("netsecdb")
		event.EventDate = eventDate

		// Set IP (validate it)
		if ip != "" {
			event.IP = ip
		} else {
			// Skip invalid IPs
			continue
		}

		result = append(result, event)
	}

	return result, nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	bodyLower := strings.ToLower(body)

	// Extract ticket ID from subject
	var ticketID string
	if match := regexp.MustCompile(`\[(?:Ticket)?#(?P<id>\d+)]`).FindStringSubmatch(subject); match != nil {
		// Find the named group
		for i, name := range regexp.MustCompile(`\[(?:Ticket)?#(?P<id>\d+)]`).SubexpNames() {
			if name == "id" && i < len(match) {
				ticketID = match[i]
				break
			}
		}
	}

	// Extract keyword from subject
	keywordMatch := regexp.MustCompile(`(?P<type>NETSECDB\S+)`).FindStringSubmatch(strings.ToUpper(subject))
	if keywordMatch == nil {
		return nil, fmt.Errorf("no NETSECDB keyword found in subject")
	}

	var keyword string
	for i, name := range regexp.MustCompile(`(?P<type>NETSECDB\S+)`).SubexpNames() {
		if name == "type" && i < len(keywordMatch) {
			keyword = keywordMatch[i]
			break
		}
	}

	// Check if keyword is in mapping
	eventMapping, ok := mapping[keyword]
	if !ok {
		return nil, fmt.Errorf("unknown keyword: %s", keyword)
	}

	// Obtain event information
	eventList, err := obtainEventInfo(bodyLower, keyword, eventMapping.requiredMarker, eventMapping.hintMarkers)
	if err != nil {
		return nil, err
	}

	// Set event types and external ID for each event
	var result []*events.Event
	for _, event := range eventList {
		event.EventTypes = []events.EventType{eventMapping.eventTypeCtor()}

		if ticketID != "" {
			event.AddEventDetail(&events.ExternalID{ID: ticketID})
		}

		// If no event date was found, use the email date
		if event.EventDate == nil {
			if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
				if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
					event.EventDate = parsedDate
				}
			}
		}

		result = append(result, event)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
