package mieweb

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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	event := events.NewEvent("mieweb")
	event.EventTypes = []events.EventType{events.NewMaliciousActivity()}

	// Parse event date
	eventDateStr := common.FindStringWithoutMarkers(body, "Timestamp:", "\n")
	eventDateStr = strings.TrimSpace(eventDateStr)
	if eventDateStr != "" {
		event.EventDate = email.ParseDate(eventDateStr)
	}

	// Parse source IP
	event.IP = common.FindStringWithoutMarkers(body, "Source IP:", "\n")

	// Parse source port
	srcPortPattern := regexp.MustCompile(`(?i)source port: (\d+)`)
	if srcPortMatch := srcPortPattern.FindStringSubmatch(body); srcPortMatch != nil {
		if port, err := common.ParsePort(srcPortMatch[1]); err == nil {
			event.Port = port
		}
	}

	// Parse destination port
	var dstPort string
	dstPortPattern := regexp.MustCompile(`(?i)destination port: (\d+)`)
	if dstPortMatch := dstPortPattern.FindStringSubmatch(body); dstPortMatch != nil {
		dstPort = dstPortMatch[1]
	}

	// Parse destination IP
	dstIP := common.FindStringWithoutMarkers(body, "Destination IP:", "(")
	dstIP = strings.TrimSpace(dstIP)

	// Add target event detail if we have destination IP
	if dstIP != "" {
		target := &events.Target{
			IP:   dstIP,
			Port: dstPort,
		}
		event.AddEventDetail(target)
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
