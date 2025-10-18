package tmclo

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	email "github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)

	// Check for the specific pattern in the body
	if strings.Contains(bodyLower, "lines containing failures of") {
		event := events.NewEvent("tmclo")
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}

		// Parse event date from email headers
		if headers := serializedEmail.Headers; headers != nil {
			if dateHeaders, ok := headers["date"]; ok && len(dateHeaders) > 0 {
				event.EventDate = email.ParseDate(dateHeaders[0])
			}
		}

		// Subject contains the IP address
		event.IP = subjectLower

		return []*events.Event{event}, nil
	}

	// Unknown email type
	return nil, common.NewNewTypeError(subjectLower)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
