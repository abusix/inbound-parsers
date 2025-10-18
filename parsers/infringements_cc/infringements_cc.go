package infringements_cc

import (
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

	event := events.NewEvent("infringements_cc")

	// Set event date from email headers
	dateFallback := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateFallback = dateHeaders[0]
		event.EventDate = email.ParseDate(dateFallback)
	}

	// Extract URL - look for "URL: " pattern
	urlLine := common.FindStringWithoutMarkers(body, "URL: ", "")
	if urlLine != "" {
		urlText := strings.TrimSpace(urlLine)
		event.URL = common.CleanURL(urlText)
	}

	// Extract IP Address - look for "IP ADDRESS: " pattern
	ipLine := common.FindStringWithoutMarkers(body, "IP ADDRESS: ", "")
	if ipLine != "" {
		ipText := strings.TrimSpace(ipLine)
		if ip := common.IsIP(ipText); ip != "" {
			event.IP = ip
		}
	}

	// Extract timestamp for event date - look for "TIMESTAMP (UTC): " pattern
	timestampLine := common.FindStringWithoutMarkers(body, "TIMESTAMP (UTC): ", "")
	if timestampLine != "" {
		timestamp := strings.TrimSpace(timestampLine)
		// Try to parse the timestamp
		if parsedDate := email.ParseDate(timestamp); parsedDate != nil {
			event.EventDate = parsedDate
		}
		// If parsing fails, keep the fallback date from email headers
	}

	// Determine copyright owner from subject
	copyrightOwner := ""
	if strings.Contains(subject, "Copyright Notification -") {
		// Extract copyright owner from subject after "Copyright Notification - "
		ownerPart := common.FindStringWithoutMarkers(subject, "Copyright Notification - ", " [")
		if ownerPart != "" {
			copyrightOwner = strings.TrimSpace(ownerPart)
		}
	}

	// Set event type as Copyright
	event.EventTypes = []events.EventType{events.NewCopyright("", copyrightOwner, "")}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
