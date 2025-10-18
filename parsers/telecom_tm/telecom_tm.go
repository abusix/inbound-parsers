// Package telecom_tm implements the Telecom Turkmenistan DDoS report parser
package telecom_tm

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the telecom_tm parser
type Parser struct{}

// Parse parses emails from @telecom.tm reporting DDoS attacks
// This parser extracts DDoS attack information including ISP, IP, target port, and attack date
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get email body
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Convert to lowercase for case-insensitive matching
	body = strings.ToLower(body)

	// Replace line breaks within words to handle word wrapping
	// Pattern: non-space + newline + non-space -> join with space
	re := regexp.MustCompile(`(\S)\r?\n(\S)`)
	body = re.ReplaceAllString(body, "$1 $2")

	// Extract fields using FindStringWithoutMarkers
	isp := strings.TrimSpace(common.FindStringWithoutMarkers(body, "we are isp", "."))
	ip := common.FindStringWithoutMarkers(body, "ip address:", "")
	targetPortStr := common.FindStringWithoutMarkers(body, "destination port:", "")
	dateStr := common.FindStringWithoutMarkers(body, "start date:", "")

	// Extract only digits from port
	var targetPort string
	for _, ch := range targetPortStr {
		if ch >= '0' && ch <= '9' {
			targetPort += string(ch)
		}
	}

	// Clean up date string (remove spaces and brackets)
	dateStr = strings.TrimSpace(dateStr)
	dateStr = strings.Trim(dateStr, "[]")
	dateStr = strings.TrimSpace(dateStr)

	// Create event
	event := events.NewEvent("telecom_tm")
	event.IP = ip
	event.EventTypes = []events.EventType{events.NewDDoS()}

	// Parse and set event date
	if dateStr != "" {
		eventDate := email.ParseDate(dateStr)
		event.EventDate = eventDate
	}

	// Add ISP detail
	if isp != "" {
		event.AddEventDetail(&events.ISP{
			ISPName: isp,
			Country: "",
		})
	}

	// Add Target detail
	event.AddEventDetail(&events.Target{
		Port: targetPort,
	})

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
