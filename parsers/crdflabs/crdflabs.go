package crdflabs

import (
	"strings"

	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
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

	var result []*events.Event
	var blocks []string

	// Check for multiple issues in body
	issueNumber := 1
	issueMarker := "Issue #1"
	if strings.Contains(body, issueMarker) {
		// Extract blocks around each issue
		for strings.Contains(body, "Issue #"+string(rune(issueNumber+'0'))) {
			block := strings.Join(common.GetBlockAround(body, "Issue #"+string(rune(issueNumber+'0'))), "\n")
			blocks = append(blocks, block)
			issueNumber++
		}
	} else {
		blocks = append(blocks, body)
	}

	for _, block := range blocks {
		// Extract IP
		ipStr := common.FindStringWithoutMarkers(block, "IP Address:", "")
		ipStr = strings.ReplaceAll(ipStr, "[.]", ".")
		ip := common.IsIP(ipStr)

		// Extract URL
		url := common.CleanURL(common.FindStringWithoutMarkers(block, "URL:", ""))

		// Extract case ID
		caseID := strings.TrimSpace(common.FindStringWithoutMarkers(block, "Ref:", ""))

		event := events.NewEvent("crdflabs")

		// Set event date
		dateCandidate := common.FindStringWithoutMarkers(block, "Timestamp:", "")
		if dateCandidate != "" {
			// Note: Would need datetime parser here, using header date for now
			if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			}
		} else {
			if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			}
		}

		// Determine event type
		eventTypeString := strings.TrimSpace(strings.ToLower(common.FindStringWithoutMarkers(block, "threat:", "")))
		if eventTypeString == "" {
			return nil, common.NewParserError("No event type detected")
		} else if strings.Contains(eventTypeString, "phishing") {
			phishing := events.NewPhishing()
			if url != "" {
				phishing.PhishingTarget = url
			}
			event.EventTypes = []events.EventType{phishing}
		} else if strings.Contains(eventTypeString, "malware") {
			event.EventTypes = []events.EventType{events.NewMalware("")}
		} else if strings.Contains(eventTypeString, "malicious") || strings.Contains(eventTypeString, "suspect") {
			event.EventTypes = []events.EventType{events.NewFraud()}
		} else {
			return nil, common.NewNewTypeError(eventTypeString)
		}

		event.IP = ip
		event.URL = url
		if caseID != "" {
			event.AddEventDetail(&events.ExternalID{ID: caseID})
		}

		result = append(result, event)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
