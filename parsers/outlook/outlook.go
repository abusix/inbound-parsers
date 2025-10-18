package outlook

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the Outlook parser for jjohanson@outlook.com and snds-authorization@outlook.com
type Parser struct{}

// NewParser creates a new Outlook parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from jjohanson@outlook.com
// Supports:
// - Spam reports with IP addresses
// - Malicious activity reports
// - Cobalt Strike malware reports
// - any.run report URLs
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	fromAddr, err := common.GetFrom(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)

	// Check if this is from jjohanson@outlook.com
	if strings.ToLower(fromAddr) == "jjohanson@outlook.com" {
		return parseJjohanson(bodyLower, serializedEmail)
	}

	// snds-authorization@outlook.com emails are handled by match logic (rejected)
	return nil, common.NewParserError("unsupported outlook sender: " + fromAddr)
}

// parseJjohanson parses emails from jjohanson@outlook.com
func parseJjohanson(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Validate expected content
	if !strings.Contains(body, "spam") && !strings.Contains(body, "any.run report") {
		return nil, common.NewNewTypeError("adapt the parser")
	}

	// Get event date from email headers
	var eventDate = (*time.Time)(nil)
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	// Get subject and extract IP addresses
	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	// Extract IP addresses from subject
	ipPattern := regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	ips := ipPattern.FindAllString(subjectLower, -1)

	if len(ips) == 0 {
		return nil, common.NewParserError("no IP addresses found in subject")
	}

	var eventsList []*events.Event

	for _, ip := range ips {
		event := events.NewEvent("jjohanson")
		event.EventDate = eventDate
		event.IP = ip

		// Determine event types based on body content
		if strings.Contains(body, "malicious") {
			event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
		}
		if strings.Contains(body, "spam") {
			event.EventTypes = []events.EventType{events.NewSpam()}
		}
		if strings.Contains(body, "cobalt strike") {
			event.EventTypes = []events.EventType{events.NewMalware("Cobalt Strike")}
		}

		// Extract URL
		url := common.GetNonEmptyLineAfter(body, "the url given:")
		if url == "" {
			url = common.GetNonEmptyLineAfter(body, "url givin in chat room:")
		}
		event.URL = url

		// Extract any.run report URL
		anyReportURL := common.GetNonEmptyLineAfter(body, "report of url activity:")
		if anyReportURL == "" {
			// Try regex pattern
			anyReportPattern := regexp.MustCompile(`(https://any\.run/report/[\w\/-]+)`)
			if matches := anyReportPattern.FindStringSubmatch(body); len(matches) > 1 {
				anyReportURL = matches[1]
			}
		}

		// Add evidence if any.run report URL found
		if anyReportURL != "" {
			evidence := &events.Evidence{}
			evidence.AddEvidence(events.UrlStore{
				Description: "any.run report",
				URL:         anyReportURL,
			})
			event.AddEventDetail(evidence)
		}

		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no events created")
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
