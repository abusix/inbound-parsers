package mail_ru

import (
	"regexp"
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
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	// Check if subject contains "haker"
	if !strings.Contains(subjectLower, "haker") {
		return nil, common.NewNewTypeError(subjectLower)
	}

	event := events.NewEvent("mail_ru")

	// Set event date from email headers
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventDate := email.ParseDate(dateHeaders[0])
			event.EventDate = eventDate
		}
	}

	// Set event type to WebHack
	event.EventTypes = []events.EventType{events.NewWebHack()}

	// Try to extract target URL and IP from "site attack" pattern
	targetRegex := regexp.MustCompile(`(?i)site\s+attack\s+(?P<url>http\S+)\s+ip\s+(?P<ip>[\d.]+)`)
	if match := targetRegex.FindStringSubmatch(body); match != nil {
		targetURL := match[1]
		targetIP := match[2]
		event.AddEventDetail(&events.Target{
			IP:  targetIP,
			URL: targetURL,
		})
	}

	// Try to extract IP from "ip:" pattern
	ipRegex := regexp.MustCompile(`(?i)ip:\s+(?P<ip>\S+)`)
	if match := ipRegex.FindStringSubmatch(body); match != nil {
		event.IP = match[1]
		return []*events.Event{event}, nil
	}

	// Try to extract IP from "visitor ip address:" pattern
	visitorIPRegex := regexp.MustCompile(`(?i)visitor ip address:\s+(?P<ip>\S+)`)
	if match := visitorIPRegex.FindStringSubmatch(body); match != nil {
		event.IP = match[1]
		return []*events.Event{event}, nil
	}

	// If no IP found, still return the event (might have target IP in event details)
	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
