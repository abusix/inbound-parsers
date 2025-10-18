package ddos_google

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

// New creates a new parser instance (wrapper for Bento integration)
func New(se email.SerializedEmail, fa, fn, ct string) *Parser {
	// Ignore the parameters - they're not needed for this parser
	_ = se
	_ = fa
	_ = fn
	_ = ct
	return NewParser()
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Get date parts from headers
	var dateParts []string
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		dateParts = strings.Split(dateHeader[0], " ")
		// Remove timezone (last element) - table date is UTC
		if len(dateParts) > 0 {
			dateParts = dateParts[:len(dateParts)-1]
		}
	}

	// Extract target IP from text around "performing DNS lookups"
	blockAround := common.GetBlockAround(body, "performing DNS lookups")
	targetIPStr := strings.Join(blockAround, " ")
	targetIP := common.ExtractOneIP(targetIPStr)

	var eventsList []*events.Event

	// Parse table rows (lines starting with |)
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "|") {
			continue
		}

		// Split by | and filter out empty entries
		parts := strings.Split(line, "|")
		var entries []string
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				entries = append(entries, trimmed)
			}
		}

		var ip, datetime, requests, targetPort string
		var currentTargetIP string

		// Parse based on number of entries
		switch len(entries) {
		case 2:
			ip = entries[0]
			datetime = entries[1]
		case 3:
			ip = entries[0]
			datetime = entries[1]
			requests = entries[2]
		case 4:
			ip = entries[0]
			currentTargetIP = entries[1]
			targetPort = entries[2]
			datetime = entries[3]
		default:
			return nil, common.NewParserError(fmt.Sprintf("unexpected number of table entries: %d", len(entries)))
		}

		// Validate IP
		validIP := common.IsIP(ip)
		if validIP == "" {
			continue
		}

		// Use the specific target IP if provided, otherwise use the one from the header
		if currentTargetIP == "" {
			currentTargetIP = targetIP
		}

		// Create event
		event := events.NewEvent("ddos_google")

		// Parse time and construct event date
		if len(dateParts) >= 5 {
			timeParts := strings.Split(datetime, " ")
			if len(timeParts) >= 2 {
				time := timeParts[1]
				// Ensure time has seconds (add :00 if needed)
				if !strings.Contains(time, ":") {
					time = time + ":00:00"
				} else if strings.Count(time, ":") == 1 {
					time = time + ":00"
				}
				// Truncate to HH:MM:SS format
				if len(time) > 8 {
					time = time[:8]
				}
				dateParts[4] = time
				event.EventDate = email.ParseDate(strings.Join(dateParts, " "))
			}
		}

		event.IP = validIP

		// Set event type with requests if available
		if requests != "" {
			event.EventTypes = []events.EventType{events.NewDDosAmplification(requests, "")}
		} else {
			event.EventTypes = []events.EventType{events.NewDDoS()}
		}

		// Add target details
		target := &events.Target{
			IP:   currentTargetIP,
			Port: targetPort,
		}
		event.AddEventDetail(target)

		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no events parsed from email")
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
