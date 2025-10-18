package vmware

import (
	"fmt"
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

// Match checks if this parser can handle the email
func (p *Parser) Match(serializedEmail *email.SerializedEmail) bool {
	fromAddr, err := common.GetFrom(serializedEmail, false)
	if err != nil {
		return false
	}

	return strings.Contains(fromAddr, "connect.vmware.com")
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get subject: %w", err)
	}

	// Check subject to determine event type
	var eventType events.EventType
	if strings.Contains(strings.ToLower(subject), "vcenter server(s)") {
		eventType = events.NewOpen("vCenter")
	} else {
		return nil, fmt.Errorf("unknown subject type: %s", subject)
	}

	// Get event date from headers
	var eventDate *events.DateTime
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = events.NewDateTime(dateHeaders[0])
	}

	// Get body from parts[1]
	if len(serializedEmail.Parts) < 2 {
		return nil, fmt.Errorf("expected at least 2 parts, got %d", len(serializedEmail.Parts))
	}

	bodyPart := serializedEmail.Parts[1]
	var body string
	switch b := bodyPart.Body.(type) {
	case string:
		body = b
	case []byte:
		body = string(b)
	default:
		return nil, fmt.Errorf("unexpected body type in parts[1]: %T", bodyPart.Body)
	}

	body = strings.ToLower(body)

	// Extract IP block
	ipBlock := common.FindStringWithoutMarkers(body, "your ip address:", "</p>")
	ipBlock = strings.TrimSpace(ipBlock)
	// Remove all spaces
	ipBlock = regexp.MustCompile(` `).ReplaceAllString(ipBlock, "")

	// Split by comma and create events
	var result []*events.Event
	for _, ip := range strings.Split(ipBlock, ",") {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}

		event := events.NewEvent("vmware")
		if eventDate != nil {
			event.Headers = map[string]interface{}{
				"event_date": eventDate.Value,
			}
		}
		event.EventTypes = []events.EventType{eventType}
		event.IP = ip

		result = append(result, event)
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no IPs found in email")
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
