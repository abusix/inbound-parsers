package obp_corsearch

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
	subjectLower := strings.ToLower(subject)

	event := events.NewEvent("obp_corsearch")
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	var result []*events.Event

	if strings.Contains(subjectLower, "trademark") {
		event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}
		event.URL = common.FindStringWithoutMarkers(body, "Infringing url:", "")
		if event.URL == "" {
			// Find between markers
			startIdx := strings.Index(body, "following domain name")
			if startIdx != -1 {
				remaining := body[startIdx+len("following domain name"):]
				endIdx := strings.Index(remaining, "(the \"Domain Name\")")
				if endIdx != -1 {
					event.URL = strings.TrimSpace(remaining[:endIdx])
				}
			}
		}
		result = append(result, event)
	} else if strings.Contains(subjectLower, "notice-id-here") || strings.Contains(body, "Domain Name Infringement:") {
		event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}
		event.URL = common.FindStringWithoutMarkers(body, "Infringement:", "")
		result = append(result, event)
	} else if strings.Contains(subjectLower, "breach of section") {
		event.EventTypes = []events.EventType{events.NewFraud()}
		cleanedBody := strings.ReplaceAll(body, "// ", "//")
		event.URL = common.GetNonEmptyLineAfter(cleanedBody, "for this domain:")
		if event.URL == "" {
			event.URL = common.FindStringWithoutMarkers(body, "Domain name -", "")
		}
		result = append(result, event)
	} else {
		return nil, common.NewNewTypeError(subjectLower)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
