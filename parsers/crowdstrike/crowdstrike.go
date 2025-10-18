package crowdstrike

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
	event := events.NewEvent("crowdstrike")

	body, _ := common.GetBody(serializedEmail, false)
	bodyLower := strings.ToLower(body)
	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	eventTypeStr := common.FindStringWithoutMarkers(bodyLower, "nature of the threat:", "supporting evidence")

	if strings.Contains(eventTypeStr, "malware") {
		event.EventTypes = []events.EventType{events.NewMalware("")}
	} else if strings.Contains(eventTypeStr, "phishing") {
		event.EventTypes = []events.EventType{events.NewPhishing()}
	} else if strings.Contains(eventTypeStr, "spam") {
		event.EventTypes = []events.EventType{events.NewSpam()}
	} else if strings.Contains(eventTypeStr, "connections") ||
		strings.Contains(eventTypeStr, "industry_reported") ||
		strings.Contains(eventTypeStr, "malicious_impersonation") {
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
	} else {
		return nil, common.NewNewTypeError(eventTypeStr)
	}

	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
	}

	ip := common.FindStringWithoutMarkers(bodyLower, "associated ip address:", "")
	if common.IsIP(ip) != "" {
		event.IP = ip
	}

	subjectClean := strings.ReplaceAll(subjectLower, "[external sender]", "")
	url := common.FindStringWithoutMarkers(subjectClean, "[", "]")
	event.URL = url

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
