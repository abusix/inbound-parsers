// Package eq_ee implements the eq_ee parser
package eq_ee

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the eq_ee parser
type Parser struct{}

// Parse parses emails from @veebimajutus2.eq.ee for malicious activity reports
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	if strings.Contains(subjectLower, "malicious activity") {
		event := events.NewEvent("eq_ee")
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
		event.IP = common.ExtractOneIP(subject)

		if strings.Contains(body, "UTC Time:") {
			dateStr := common.FindStringWithoutMarkers(body, "UTC Time:", "UTC")
			event.EventDate = email.ParseDate(dateStr)
		} else if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}

		return []*events.Event{event}, nil
	}

	return nil, common.NewNewTypeError(subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
