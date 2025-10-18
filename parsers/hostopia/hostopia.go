package hostopia

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	pkgemail "github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *pkgemail.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	// Check if this is a spam report
	if !strings.Contains(strings.ToLower(subject), "spam") {
		return nil, common.NewParserError("unsupported report type: " + subject)
	}

	event := events.NewEvent("hostopia")
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Set event date from headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		if parsed := pkgemail.ParseDate(dateHeader[0]); parsed != nil {
			event.EventDate = parsed
		}
	}

	// Extract domain/email
	domainRe := regexp.MustCompile(`(?i)(Domain/Email\s*:\s*-?)\s*(?P<domain>.*)`)
	if match := domainRe.FindStringSubmatch(body); len(match) > 2 {
		email := strings.TrimSpace(match[2])
		if strings.Contains(email, "@") {
			// Split email to get domain
			parts := strings.Split(email, "@")
			if len(parts) > 1 {
				event.URL = parts[1]
			}
			event.AddEventDetail(&events.Email{
				FromAddress: email,
			})
		} else {
			event.URL = email
		}
	}

	// Extract issue
	issueRe := regexp.MustCompile(`(?i)(Issue\s*:\s*-?)\s*(?P<issue>.*)`)
	if match := issueRe.FindStringSubmatch(body); len(match) > 2 {
		issue := strings.TrimSpace(match[2])
		if event.Headers == nil {
			event.Headers = make(map[string]interface{})
		}
		event.Headers["Issue"] = issue
	}

	// Extract action taken
	actionRe := regexp.MustCompile(`(?i)(action taken\s*:\s*-?)\s*(?P<action>.*)`)
	if match := actionRe.FindStringSubmatch(body); len(match) > 2 {
		action := strings.TrimSpace(match[2])
		if event.Headers == nil {
			event.Headers = make(map[string]interface{})
		}
		event.Headers["Action Taken"] = action
	}

	// Extract Hostopia ticket number
	ticketRe := regexp.MustCompile(`(?i)(Hostopia ticket #\s*:\s*-?)\s*(?P<ticket_id>.*)`)
	if match := ticketRe.FindStringSubmatch(body); len(match) > 2 {
		ticketID := strings.TrimSpace(match[2])
		event.AddEventDetail(&events.ExternalID{
			ID: ticketID,
		})
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
