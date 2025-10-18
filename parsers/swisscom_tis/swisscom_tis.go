package swisscom_tis

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

var evidenceHeaderCandidates = []string{
	"x-fxit-ip",
	"x-originating-ip",
	"x-vadesecure-originating-ip",
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	event := events.NewEvent("swisscom_tis")
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Check if we have parts
	if len(serializedEmail.Parts) == 0 {
		return nil, fmt.Errorf("no parts found in email")
	}

	// Get evidence headers from first part
	evidenceHeaders := serializedEmail.Parts[0].Headers
	if evidenceHeaders == nil {
		return nil, fmt.Errorf("no headers found in first part")
	}

	// Try to find IP from evidence header candidates
	var foundIP string
	for _, candidate := range evidenceHeaderCandidates {
		if values, ok := evidenceHeaders[candidate]; ok && len(values) > 0 {
			foundIP = values[0]
			event.IP = foundIP
			break
		}
	}

	// If no IP found in candidates, check Received headers
	if event.IP == "" {
		if receivedHeaders, ok := evidenceHeaders["received"]; ok && len(receivedHeaders) > 0 {
			// Try to extract IP from received header
			// This is a fallback, the Python parser just checks for existence
			// We'll set a placeholder or try to extract
			// For now, we'll return an error as per Python logic
		}

		if event.IP == "" {
			return nil, fmt.Errorf("could not find any header to extract event IP from")
		}
	}

	// Handle event date extraction
	// First check for x-fxit-ip with Epoch timestamp
	if xFxitValues, ok := evidenceHeaders["x-fxit-ip"]; ok && len(xFxitValues) > 0 {
		xFxitIP := xFxitValues[0]
		if strings.Contains(xFxitIP, "Epoch[") {
			// Extract epoch timestamp
			epochStr := common.FindStringWithoutMarkers(xFxitIP, "Epoch[", "]")
			if epochStr != "" {
				if epochInt, err := strconv.ParseInt(epochStr, 10, 64); err == nil {
					// Try as seconds first
					eventDate := time.Unix(epochInt, 0).UTC()

					// Check if this is a reasonable timestamp (not too far in future/past)
					// If it seems like milliseconds (too large), convert
					now := time.Now()
					if eventDate.Year() > now.Year()+10 {
						// Likely milliseconds
						eventDate = time.Unix(epochInt/1000, (epochInt%1000)*1000000).UTC()
					}

					event.EventDate = &eventDate
				}
			}
		}
	}

	// If no event date yet, try to get from date header
	if event.EventDate == nil {
		if dateValues, ok := evidenceHeaders["date"]; ok && len(dateValues) > 0 {
			if parsedDate := email.ParseDate(dateValues[0]); parsedDate != nil {
				event.EventDate = parsedDate
			}
		}
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
