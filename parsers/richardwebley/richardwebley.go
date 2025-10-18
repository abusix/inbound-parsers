package richardwebley

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

var (
	// Pattern for date like "Oct 18 14:23:45"
	attackDatePattern = regexp.MustCompile(`\w{3}\s+\d{2}\s+\d{2}:\d{2}:\d{2}`)
	// Pattern for IP address extraction: "their ip address is: 1.2.3.4"
	theirIPPattern = regexp.MustCompile(`their\s+ip\s+address(\s+is|\s+is:)*\s+(?P<ip>(\d|\.)+)`)
	// Pattern for phishing email date like "Mon, 18 Oct 2024 14:23:45"
	phishingDatePattern = regexp.MustCompile(`\w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2}`)
)

func NewParser() *Parser {
	return &Parser{}
}

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

	// Get event date from email headers
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	// Handle FTP/HTTP attack reports
	if strings.Contains(subjectLower, "ftp attack") || strings.Contains(subjectLower, "http attack") {
		event := events.NewEvent("richardwebley")
		event.EventDate = eventDate
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}

		// Extract date from body (e.g., "Oct 18 14:23:45")
		dateMatch := attackDatePattern.FindString(body)
		if dateMatch != "" {
			// Parse date with format "Oct 18 14:23:45" and add current year
			parsedDate, parseErr := time.Parse("Jan 02 15:04:05", dateMatch)
			if parseErr == nil && eventDate != nil {
				// Set the year from the event date
				parsedDate = time.Date(
					eventDate.Year(),
					parsedDate.Month(),
					parsedDate.Day(),
					parsedDate.Hour(),
					parsedDate.Minute(),
					parsedDate.Second(),
					0,
					eventDate.Location(),
				)
				event.EventDate = &parsedDate
			}
		}

		// Extract source IP address
		ipMatch := theirIPPattern.FindStringSubmatch(body)
		if len(ipMatch) > 0 {
			// Get the named group 'ip'
			for i, name := range theirIPPattern.SubexpNames() {
				if name == "ip" && i < len(ipMatch) {
					event.IP = ipMatch[i]
					break
				}
			}
		}

		// Extract target IP (W.A.N address)
		targetIP := common.FindStringWithoutMarkers(body, "My W.A.N address is currently", ". ")
		if targetIP != "" {
			event.AddEventDetail(&events.Target{IP: targetIP})
		}

		if event.IP != "" {
			return []*events.Event{event}, nil
		}

		return nil, common.NewParserError("failed to extract IP address from attack report")
	}

	// Handle phishing email reports
	if strings.Contains(subjectLower, "phishing email") {
		event := events.NewEvent("richardwebley")
		event.EventDate = eventDate
		event.EventTypes = []events.EventType{events.NewPhishing()}

		// Extract IP address
		event.IP = common.FindStringWithoutMarkers(body, "I.P Address", ". ")

		// Extract date from body (e.g., "Mon, 18 Oct 2024 14:23:45")
		dateMatch := phishingDatePattern.FindString(body)
		if dateMatch != "" {
			parsedDate := email.ParseDate(dateMatch)
			if parsedDate != nil {
				event.EventDate = parsedDate
			}
		}

		if event.IP != "" {
			return []*events.Event{event}, nil
		}

		return nil, common.NewParserError("failed to extract IP address from phishing report")
	}

	// Unknown subject type
	return nil, common.NewParserError(fmt.Sprintf("unknown subject type: %s", subjectLower))
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
