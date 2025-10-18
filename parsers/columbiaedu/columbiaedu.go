package columbiaedu

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

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("no email body found")
	}

	var result []*events.Event

	// Process each line in the body
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		// Look for lines containing "->"
		if !strings.Contains(line, "->") {
			continue
		}

		// Extract all IPv4 addresses from the line
		ips := common.ExtractAllIPv4(line)
		if len(ips) < 2 {
			continue
		}

		sourceIP := ips[0]
		targetIP := ips[1]

		// Extract source port (number after sourceIP:)
		sourcePortPattern := regexp.MustCompile(regexp.QuoteMeta(sourceIP) + `:(\d+)`)
		sourcePortMatch := sourcePortPattern.FindStringSubmatch(line)
		if len(sourcePortMatch) < 2 {
			continue
		}
		sourcePortStr := sourcePortMatch[1]

		// Extract target port (number after targetIP:)
		targetPortPattern := regexp.MustCompile(regexp.QuoteMeta(targetIP) + `:(\d+)`)
		targetPortMatch := targetPortPattern.FindStringSubmatch(line)
		if len(targetPortMatch) < 2 {
			continue
		}
		targetPortStr := targetPortMatch[1]

		// Parse ports to integers
		sourcePort, err := common.ParsePort(sourcePortStr)
		if err != nil {
			continue
		}

		// Extract dateline from first 3 words, replace GTM with empty string
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		dateline := strings.Join(fields[:3], " ")
		dateline = strings.ReplaceAll(dateline, "GTM", "")
		dateline = strings.TrimSpace(dateline)

		// Parse the datetime
		parsedDate := email.ParseDate(dateline)

		// Create event
		event := events.NewEvent("columbiaedu")
		event.IP = sourceIP
		event.Port = sourcePort
		event.EventDate = parsedDate
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

		// Add target detail (port is stored as string in Target)
		event.AddEventDetail(&events.Target{
			IP:   targetIP,
			Port: targetPortStr,
		})

		result = append(result, event)
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no events extracted from email")
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
