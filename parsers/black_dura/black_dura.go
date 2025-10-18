package black_dura

import (
	"strconv"
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

	// Check if this is an "anomalous activity" report
	if !strings.Contains(subjectLower, "anomalous activity") {
		return nil, nil
	}

	event := events.NewEvent("black_dura")
	event.EventTypes = []events.EventType{events.NewMaliciousActivity()}

	// Extract event date/time
	eventDateStr := common.GetNonEmptyLineAfter(body, "Timestamp of the Incident (UTC):")
	if eventDateStr != "" {
		event.EventDate = email.ParseDate(eventDateStr)
	}

	// Extract source IP and port
	event.IP = common.GetNonEmptyLineAfter(body, "Source Server IP Address:")
	portStr := common.GetNonEmptyLineAfter(body, "Source Port:")
	if portStr != "" {
		// Port is stored as string in Go as well, just convert if needed
		event.Port, _ = strconv.Atoi(portStr)
	}

	// Extract target information
	targetIP := common.GetNonEmptyLineAfter(body, "Targeted Server IP Address:")
	targetPort := common.GetNonEmptyLineAfter(body, "Target Port:")

	// Handle "None" value for target port
	if strings.TrimSpace(targetPort) == "None" {
		targetPort = ""
	}

	// Add target as event detail
	if targetIP != "" || targetPort != "" {
		target := &events.Target{
			IP:   targetIP,
			Port: targetPort,
		}
		event.AddEventDetail(target)
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
