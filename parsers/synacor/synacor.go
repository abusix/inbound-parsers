package synacor

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
	subject, _ := common.GetSubject(serializedEmail, false)

	// Check for rejection patterns
	if strings.HasPrefix(subject, "Too many Recipients from") ||
		strings.HasPrefix(subject, "Too many Messages from") {
		return nil, common.NewParserError("rejected: too many recipients/messages report")
	}

	// Check for blacklist patterns
	subjectLower := strings.ToLower(subject)
	if !strings.Contains(subjectLower, "black list") &&
		!strings.Contains(subjectLower, "sbl/xbl block") {
		return nil, common.NewParserError("subject does not match blacklist patterns")
	}

	// Get body and header date
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	var headerDate string
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		headerDate = dateHeader[0]
	}

	return parseBlacklist(body, headerDate, subject), nil
}

func parseBlacklist(body, headerDate, subject string) []*events.Event {
	event := events.NewEvent("synacor")

	// Set event date
	if headerDate != "" {
		event.EventDate = email.ParseDate(headerDate)
	}

	// Add subject to headers
	if subject != "" {
		event.Headers["subject"] = subject
	}

	// Parse body line by line
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		lineLower := strings.ToLower(line)

		// Look for X-Originating-IP header
		if strings.HasPrefix(lineLower, "x-originating-ip:") {
			// Extract IP from the line
			ip := common.ExtractOneIP(line)
			validIP := common.IsIP(ip)
			if validIP != "" {
				event.IP = validIP
			}
		} else if strings.HasPrefix(lineLower, "x-zimbra") {
			// Extract X-Zimbra headers
			// Split by the last colon to get key and value
			if colonIdx := strings.LastIndex(line, ":"); colonIdx != -1 {
				key := line[:colonIdx]
				value := strings.TrimSpace(line[colonIdx+1:])
				if value != "" {
					event.Headers[key] = value
				}
			}
		}
	}

	// Set event type
	event.EventTypes = []events.EventType{events.NewBlacklist("")}

	return []*events.Event{event}
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
