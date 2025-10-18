package cert_gov

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

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	event := events.NewEvent("cert_gov")

	// Set event_date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	// Extract external_id from subject [...]
	externalID := common.FindStringWithoutMarkers(subject, "[", "]")
	if externalID != "" {
		event.AddEventDetail(&events.ExternalID{ID: externalID})
	}

	// Route to appropriate parsing function based on subject/body
	if strings.Contains(subjectLower, "spam") {
		return p.parseSpam(body, subject, event)
	} else if strings.Contains(subjectLower, "phishing") {
		return p.parsePhishing(body, event)
	} else if strings.Contains(subjectLower, "port - scanning") || strings.Contains(body, "scanning attempts") {
		return p.parsePortScan(body, subject, event)
	} else if strings.Contains(subjectLower, "malware") {
		return p.parseMalware(body, event)
	} else if strings.Contains(body, "brute force attempts") {
		return p.parseLoginAttack(body, event)
	}

	return nil, fmt.Errorf("unknown subject type: %s", subjectLower)
}

func (p *Parser) parseSpam(body, subject string, event *events.Event) ([]*events.Event, error) {
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Try to parse date like: Wed, 02 Jan 2024 12:00:00 +0000
	dateRegex := regexp.MustCompile(`\s+\w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2} (\+|-)\d{4}`)
	if dateMatch := dateRegex.FindString(body); dateMatch != "" {
		if parsedDate := email.ParseDate(strings.TrimSpace(dateMatch)); parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	if strings.Contains(body, "Server:") {
		event.URL = common.FindStringWithoutMarkers(body, "Server:", " -")
		event.IP = common.FindStringWithoutMarkers(body, "Server:", "")
	} else {
		event.IP = subject
	}

	return []*events.Event{event}, nil
}

func (p *Parser) parsePhishing(body string, event *events.Event) ([]*events.Event, error) {
	event.EventTypes = []events.EventType{events.NewPhishing()}

	// Remove "> " prefixes (quoted reply markers)
	body = regexp.MustCompile(`\s+>\s+`).ReplaceAllString(body, "")

	// Try first pattern: URL * IP
	eventRegex1 := regexp.MustCompile(`(?i)(?P<url>(http|hxxp)\S+)\s+\*\s+(?P<ip>(\.|\d)+)`)
	if matches := eventRegex1.FindStringSubmatch(body); matches != nil {
		event.URL = matches[1] // url group
		event.IP = matches[3]  // ip group
		return []*events.Event{event}, nil
	}

	// Try second pattern: URL with spaces, then IP
	eventRegex2 := regexp.MustCompile(`(?i)(?P<url>(http|hxxp)\S+\s+\S+)\s+(?P<ip>(\.|\d)+)`)
	if matches := eventRegex2.FindStringSubmatch(body); matches != nil {
		// Remove whitespace from URL
		url := strings.ReplaceAll(matches[1], " ", "")
		event.URL = url
		event.IP = matches[3] // ip group
		return []*events.Event{event}, nil
	}

	return []*events.Event{event}, nil
}

func (p *Parser) parseLoginAttack(body string, event *events.Event) ([]*events.Event, error) {
	event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

	// Parse date in format: 2024-01-02:12:30:45
	dateRegex := regexp.MustCompile(`\d{4}-\d{2}-\d{2}:\d{2}:\d{2}:\d{2}`)
	if dateMatch := dateRegex.FindString(body); dateMatch != "" {
		// Parse the custom format
		if parsedDate, err := time.Parse("2006-01-02:15:04:05", dateMatch); err == nil {
			event.EventDate = &parsedDate
		}
	}

	// Get IP from line after "your authority."
	event.IP = common.GetNonEmptyLineAfter(body, "your authority.")

	return []*events.Event{event}, nil
}

func (p *Parser) parseMalware(body string, event *events.Event) ([]*events.Event, error) {
	event.EventTypes = []events.EventType{events.NewMalware("")}

	// Try pattern: URL * IP
	eventRegex := regexp.MustCompile(`(?i)(?P<url>(http|hxxp)\S+)\s+\*\s+(?P<ip>(\.|\d)+)`)
	if matches := eventRegex.FindStringSubmatch(body); matches != nil {
		event.URL = matches[1] // url group
		event.IP = matches[3]  // ip group
	}

	return []*events.Event{event}, nil
}

func (p *Parser) parsePortScan(body, subject string, event *events.Event) ([]*events.Event, error) {
	event.EventTypes = []events.EventType{events.NewPortScan()}

	// Parse date in format: 2024/01/02 12:30
	dateRegex := regexp.MustCompile(`\d{4}/\d{2}/\d{2} \d{2}:\d{2}`)
	if dateMatch := dateRegex.FindString(body); dateMatch != "" {
		if parsedDate, err := time.Parse("2006/01/02 15:04", dateMatch); err == nil {
			event.EventDate = &parsedDate
		}
	}

	event.IP = subject

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
