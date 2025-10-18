package comvive

import (
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

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	var ip string
	var eventDate *time.Time
	var eventType events.EventType
	var attackedDomain string

	// Check if it's a network/ddos attack (from subject)
	if strings.Contains(subjectLower, "network attack") || strings.Contains(subjectLower, "ddos attack") {
		ip = common.ExtractOneIP(subject)
		ip = common.IsIP(ip)

		// Get date from email headers
		if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
			eventDate = email.ParseDate(dateHeader[0])
		}

		eventType = events.NewDDoS()

	} else {
		// Login attack - parse from body
		body, err := common.GetBody(serializedEmail, false)
		if err != nil || body == "" {
			return nil, common.NewParserError("no email body found")
		}

		// Extract attacked domain
		marker := "\nDomain: "
		startIndex := strings.Index(body, marker)
		if startIndex != -1 {
			startIndex += len(marker)
			endIndex := strings.Index(body[startIndex:], "\n")
			if endIndex != -1 {
				attackedDomain = body[startIndex : startIndex+endIndex]
			}
		}

		// Extract IP and date from "Lines containing IP" section
		marker = "\nLines containing IP"
		markerIndex := strings.Index(body, marker)
		if markerIndex != -1 {
			// Skip to the next double newline (after header)
			afterMarker := body[markerIndex+1:]
			doubleNewlineIndex := strings.Index(afterMarker, "\n\n")
			if doubleNewlineIndex != -1 {
				startIndex := markerIndex + 1 + doubleNewlineIndex + 2 // skip the "\n\n"
				// Find the next double newline (end of section)
				endIndex := strings.Index(body[startIndex:], "\n\n")
				if endIndex != -1 {
					section := body[startIndex : startIndex+endIndex]
					lines := strings.Split(section, "\n")
					// Filter out empty lines
					var nonEmptyLines []string
					for _, line := range lines {
						if strings.TrimSpace(line) != "" {
							nonEmptyLines = append(nonEmptyLines, line)
						}
					}
					if len(nonEmptyLines) > 0 {
						// Get the last non-empty line
						line := nonEmptyLines[len(nonEmptyLines)-1]

						// Find content between ':' and ']'
						colonIndex := strings.Index(line, ":")
						bracketIndex := strings.Index(line, "]")
						if colonIndex != -1 && bracketIndex != -1 && colonIndex < bracketIndex {
							// Extract substring between : and ]
							extracted := line[colonIndex+1 : bracketIndex]

							// IP extraction: partition by space, take first part
							spaceParts := strings.SplitN(strings.TrimSpace(extracted), " ", 2)
							if len(spaceParts) > 0 {
								ip = common.IsIP(spaceParts[0])
							}

							// Date extraction: partition by '[', take last part
							bracketParts := strings.SplitN(extracted, "[", 2)
							if len(bracketParts) > 1 {
								eventDate = email.ParseDate(bracketParts[1])
							}
						}
					}
				}
			}
		}

		eventType = events.NewLoginAttack("", "")
	}

	// Only create event if we have IP and date
	if ip != "" && eventDate != nil {
		event := events.NewEvent("comvive")
		event.IP = ip
		event.EventDate = eventDate
		event.EventTypes = []events.EventType{eventType}

		if attackedDomain != "" {
			event.AddEventDetail(&events.Target{
				URL: attackedDomain,
			})
		}

		return []*events.Event{event}, nil
	}

	return nil, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
