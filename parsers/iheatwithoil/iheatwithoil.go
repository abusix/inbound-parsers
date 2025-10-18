package iheatwithoil

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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	body = strings.ToLower(body)

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subject = strings.ToLower(subject)

	if strings.Contains(subject, "hacking scanner originating from your network") {
		return parseWebHack(body, serializedEmail)
	}

	return nil, common.NewNewTypeError(subject)
}

func parseWebHack(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Split on the marker text
	parts := strings.Split(body, "logs below, timestamps in utc")
	if len(parts) < 2 {
		return nil, common.NewParserError("could not find log delimiter in iheatwithoil email")
	}

	infoBlock := parts[1]
	lines := strings.Split(infoBlock, "\n")

	// Filter out empty lines
	var usefulInfo []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && trimmed != "\r" {
			usefulInfo = append(usefulInfo, line)
		}
	}

	var resultEvents []*events.Event

	for _, line := range usefulInfo {
		event := events.NewEvent("iheatwithoil")
		event.EventTypes = []events.EventType{events.NewWebHack()}

		// Extract IP from the beginning of the line
		// Format: "IP - - [timestamp] ..."
		ipParts := strings.Split(line, " - - ")
		if len(ipParts) > 0 {
			ip := strings.TrimSpace(ipParts[0])
			if validIP := common.IsIP(ip); validIP != "" {
				event.IP = validIP
			}
		}

		// Extract event date from between [ and ]
		eventDate := common.FindStringWithoutMarkers(line, "[", "]")
		if eventDate != "" {
			if parsed := email.ParseDate(eventDate); parsed != nil {
				event.EventDate = parsed
			}
		}

		resultEvents = append(resultEvents, event)
	}

	return resultEvents, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
