package nsc

import (
	"fmt"
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
	var result []*events.Event

	// Get body using helper - throws error if body is empty
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	event := events.NewEvent("nsc")

	if len(body) > 0 {
		bodySplit := strings.Split(body, "\n")

		for i := 0; i < len(bodySplit); i++ {
			line := bodySplit[i]

			// Parse Time line
			if strings.HasPrefix(line, "Time:") {
				indexStart := strings.Index(line, "Time: ") + len("Time: ")
				indexEnd := strings.Index(line, "(GMT")
				indexSign := strings.Index(line, "GMT ") + len("GMT ")

				if indexStart > 0 && indexEnd > 0 && indexSign > 0 {
					// Check if timezone offset is single digit (e.g., GMT +9)
					if indexSign+2 < len(line) && line[indexSign+2] == ')' {
						// Single digit offset: GMT +9
						eventDate := fmt.Sprintf("%s%c0%c:00",
							line[indexStart:indexEnd],
							line[indexSign],
							line[indexSign+1],
						)
						event.EventDate = email.ParseDate(eventDate)
					} else if indexSign+2 < len(line) {
						// Double digit offset: GMT +09
						eventDate := fmt.Sprintf("%s%c1%c:00",
							line[indexStart:indexEnd],
							line[indexSign],
							line[indexSign+2],
						)
						event.EventDate = email.ParseDate(eventDate)
					}
				}
			}

			// Parse Attacking IP line
			if strings.HasPrefix(line, "Attacking IP:") {
				event.IP = common.ExtractOneIP(line)
			}

			// Parse Event Name line
			if strings.HasPrefix(line, "Event Name:") {
				_, evtName, found := strings.Cut(line, ": ")
				if found {
					event.AddEventDetailSimple("event name", evtName)
				}
			}
		}

		// Set event type to Exploit
		event.EventTypes = []events.EventType{events.NewExploit()}
		result = append(result, event)
	}

	if len(result) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
