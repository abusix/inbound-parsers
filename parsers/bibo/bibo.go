package bibo

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get email body and subject
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	bodyLower := strings.ToLower(body)

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Verify subject contains expected marker
	if !strings.Contains(subject, "scan and attack") {
		return nil, fmt.Errorf("unexpected subject format: %s", subject)
	}

	// Extract source IP from subject
	sourceIP := common.ExtractOneIP(subject)
	if sourceIP == "" {
		return nil, fmt.Errorf("could not extract IP from subject")
	}

	// Split logs by 'regards' and extract attack logs
	parts := strings.Split(bodyLower, "regards")
	if len(parts) == 0 {
		return nil, fmt.Errorf("could not find 'regards' marker in email body")
	}

	logsPart := parts[0]
	logSections := strings.Split(logsPart, "\nattack log")
	if len(logSections) < 2 {
		return nil, fmt.Errorf("mail format changed - adapt the parser")
	}

	// Process each attack log (skip first element which is before first "attack log")
	logs := logSections[1:]
	var resultEvents []*events.Event
	seenPorts := make(map[string]bool)

	for _, log := range logs {
		// Extract source port
		port := strings.TrimSpace(common.FindStringWithoutMarkers(log, "src_port ", ""))
		if port == "" {
			continue
		}

		// Skip if we've already processed this source port
		if seenPorts[port] {
			continue
		}
		seenPorts[port] = true

		// Extract target information
		targetIP := strings.TrimSpace(common.FindStringWithoutMarkers(log, "dst ", ""))
		targetPort := strings.TrimSpace(common.FindStringWithoutMarkers(log, "dst_port ", ""))

		// Extract date/time information
		date := common.FindStringWithoutMarkers(log, "date ", "")
		timeStr := common.FindStringWithoutMarkers(log, "time ", "")
		timezone := common.FindStringWithoutMarkers(log, "timezone", "")

		// Parse timezone offset (format: +HH:MM or timezone text)
		var timezoneOffset string
		if strings.Contains(timezone, "+") {
			parts := strings.Split(timezone, "+")
			if len(parts) > 1 {
				tzParts := strings.Split(parts[1], ":")
				if len(tzParts) > 0 {
					// Pad timezone hour with zero
					tzHour := tzParts[0]
					if len(tzHour) == 1 {
						tzHour = "0" + tzHour
					}
					timezoneOffset = "+" + tzHour + ":00"
				}
			}
		}

		// Construct datetime string
		dateTime := fmt.Sprintf("%s %s %s", date, timeStr, timezoneOffset)

		// Parse datetime
		var eventDate *time.Time
		if dateTime != "  " {
			// Try to parse the datetime
			parsedTime, err := time.Parse("2006-01-02 15:04:05 -07:00", dateTime)
			if err == nil {
				eventDate = &parsedTime
			}
		}

		// Extract case information
		externalID := common.FindStringWithoutMarkers(log, "log_id ", "")
		severityLevel := common.FindStringWithoutMarkers(log, "severity_level ", "")

		// Extract protocol
		protocol := common.FindStringWithoutMarkers(log, "proto ", "")

		// Extract HTTP method
		httpMethod := common.FindStringWithoutMarkers(log, "http_method ", "")

		// Extract service and URL
		service := common.FindStringWithoutMarkers(log, "service", "")
		targetURL := common.FindStringWithoutMarkers(log, "http_url ", "")

		// Extract username
		username := common.FindStringWithoutMarkers(log, "user_name ", "")
		if username == "unknown" {
			username = ""
		}

		// Create event
		event := events.NewEvent("bibo")
		event.IP = sourceIP

		// Convert port to int
		if portInt, err := strconv.Atoi(port); err == nil {
			event.Port = portInt
		}

		// Set event type with username
		event.EventTypes = []events.EventType{events.NewLoginAttack(username, "")}

		// Set event date
		if eventDate != nil {
			event.EventDate = eventDate
		}

		// Add external case information
		if externalID != "" || severityLevel != "" {
			event.AddEventDetail(&events.ExternalCaseInformation{
				CaseID:   externalID,
				Severity: severityLevel,
			})
		}

		// Add transport protocol
		if protocol != "" {
			event.AddEventDetail(&events.TransportProtocol{
				Protocol: protocol,
			})
		}

		// Add HTTP method
		if httpMethod != "" {
			event.AddEventDetail(&events.HttpRequest{
				Method: httpMethod,
			})
		}

		// Add target information
		if targetIP != "" || targetPort != "" || targetURL != "" || service != "" {
			event.AddEventDetail(&events.Target{
				IP:      targetIP,
				Port:    targetPort,
				URL:     targetURL,
				Service: service,
			})
		}

		resultEvents = append(resultEvents, event)
	}

	if len(resultEvents) == 0 {
		return nil, fmt.Errorf("no events created")
	}

	return resultEvents, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
