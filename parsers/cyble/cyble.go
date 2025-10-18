package cyble

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
	// Get event date from headers
	var eventDate *string
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = &dateHeaders[0]
	}

	body, _ := common.GetBody(serializedEmail, false)
	// Replace specific strings that appear in the body
	body = strings.ReplaceAll(body, "the URL", "URL")
	body = strings.ReplaceAll(body, "the mentioned URL", "URL")

	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	var result []*events.Event

	// Check for trademark infringement
	if strings.Contains(body, "trademark") {
		event := events.NewEvent("cyble")
		if eventDate != nil {
			event.EventDate = email.ParseDate(*eventDate)
		}
		event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}

		// Try multiple patterns to extract the URL
		if url := common.FindStringWithoutMarkers(body, "We recently became aware of URL", "which you"); url != "" {
			event.URL = url
		} else if url := common.FindStringWithoutMarkers(body, "reported URL in order to disguise or phish the general public.", "The use of"); url != "" {
			event.URL = url
		} else {
			event.URL = common.FindStringWithoutMarkers(body, "URL", "The use of")
		}

		result = append(result, event)
	} else if strings.Contains(subjectLower, "copyright") {
		// Check for copyright infringement
		event := events.NewEvent("cyble")
		if eventDate != nil {
			event.EventDate = email.ParseDate(*eventDate)
		}
		event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}

		// Try multiple patterns to extract the URL
		if url := common.FindStringWithoutMarkers(body, "We recently became aware of URL", "which you"); url != "" {
			event.URL = url
		} else {
			event.URL = common.GetNonEmptyLineAfter(body, "Infringing URL")
		}

		result = append(result, event)
	} else {
		// Unknown type - return error
		return nil, common.NewNewTypeError(subjectLower)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
