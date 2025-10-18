package spamhaus

import (
	"fmt"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	if strings.Contains(subjectLower, "sbl notify") {
		return parseSBLNotify(serializedEmail)
	} else if strings.Contains(subjectLower, "spamhaus notification") {
		return parseNotification(serializedEmail)
	}

	return nil, fmt.Errorf("unrecognized subject: %s", subject)
}

// parseSBLNotify handles "SBL Notify" type emails
func parseSBLNotify(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	ipCIDR := common.FindString(body, "IP/cidr: ", "\n")
	problem := common.FindString(body, "Problem: ", "\n")
	sblRef := common.FindString(body, "SBL Ref: ", "\n")

	event := events.NewEvent("spamhaus")
	event.IP = subject
	event.EventTypes = []events.EventType{events.NewDNSBlocklist()}

	// Set event date from email headers
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventDate := email.ParseDate(dateHeaders[0])
			event.EventDate = eventDate
		}
	}

	// Add event details
	if ipCIDR != "" {
		cleaned := strings.TrimPrefix(ipCIDR, "IP/cidr: ")
		cleaned = strings.TrimSpace(cleaned)
		event.AddEventDetailSimple("ip_cidr", cleaned)
	}
	if problem != "" {
		cleaned := strings.TrimPrefix(problem, "Problem: ")
		cleaned = strings.TrimSpace(cleaned)
		event.AddEventDetailSimple("problem", cleaned)
	}
	if sblRef != "" {
		cleaned := strings.TrimPrefix(sblRef, "SBL Ref: ")
		cleaned = strings.TrimSpace(cleaned)
		event.AddEventDetailSimple("sbl_ref", cleaned)
	}

	return []*events.Event{event}, nil
}

// parseNotification handles "Spamhaus Notification" type emails
func parseNotification(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	bodyLower := strings.ToLower(body)

	ip := common.FindString(bodyLower, "ip address: ", "\n")
	ip = strings.TrimSpace(ip)

	issue := common.FindString(bodyLower, "issue: ", "\n")
	issue = strings.TrimSpace(issue)

	malware := common.FindString(bodyLower, "malware: ", "\n")
	malware = strings.TrimSpace(malware)

	event := events.NewEvent("spamhaus")
	event.IP = ip

	// Set event date from email headers
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventDate := email.ParseDate(dateHeaders[0])
			event.EventDate = eventDate
		}
	}

	// Determine event type based on issue content
	if strings.Contains(issue, "botnet") {
		event.EventTypes = []events.EventType{events.NewBot(malware)}
		return []*events.Event{event}, nil
	}

	return nil, fmt.Errorf("unrecognized issue type: %s", issue)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
