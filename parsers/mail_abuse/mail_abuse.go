package mail_abuse

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser handles mail-abuse.com parser logic
type Parser struct{}

// NewParser creates a new mail_abuse parser
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from jamespauloj@mail-abuse.com
// This parser extracts IPs listed in RBL reports with corresponding spam samples
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get email body
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Get date from headers
	var eventDate string
	if serializedEmail.Headers != nil {
		if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
			eventDate = dates[0]
		}
	}

	// Find sample block between markers
	sampleBlock := common.FindString(
		body,
		"-- Example of spam mail --",
		"-- End of Example of spam mail --",
	)

	// Find IP block between markers (without markers in result)
	ipBlock := common.FindStringWithoutMarkers(
		body,
		"-- IPs listed to the RBL --",
		"-- End of IPs listed to the RBL --",
	)

	var result []*events.Event

	// Process each line in the IP block
	for _, line := range strings.Split(ipBlock, "\n") {
		line = strings.TrimSpace(line)

		// Check if line is a valid IP
		if ip := common.IsIP(line); ip != "" {
			// Create new event for this IP
			event := events.NewEvent("mail_abuse")

			// Set event date
			if eventDate != "" {
				parsedDate := email.ParseDate(eventDate)
				event.EventDate = parsedDate
			}

			// Set event type to Blacklist
			event.EventTypes = []events.EventType{events.NewBlacklist("")}

			// Set IP
			event.IP = ip

			// Find sample for this IP
			sampleStart := "- [" + ip + "]"
			sample := common.FindStringWithoutMarkers(sampleBlock, sampleStart, "Spam Sample")

			// If first attempt fails, try alternative end marker
			if sample == "" {
				sample = common.FindStringWithoutMarkers(
					sampleBlock,
					sampleStart,
					"-- End of Example of spam mail --",
				)
			}

			// Add sample if found
			if sample != "" {
				event.AddEventDetail(&events.Sample{
					Payload: sample,
				})
			}

			result = append(result, event)
		}
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
