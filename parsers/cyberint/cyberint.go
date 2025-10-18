package cyberint

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
	// Get event date from email header
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	// Get body - try GetBody first, fallback to last part
	body, err := common.GetBody(serializedEmail, true)
	if err != nil || body == "" {
		// Fallback to last part body if available
		if len(serializedEmail.Parts) > 0 {
			lastPart := serializedEmail.Parts[len(serializedEmail.Parts)-1]
			switch b := lastPart.Body.(type) {
			case string:
				body = b
			case []byte:
				body = string(b)
			}
		}
	}

	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	var results []*events.Event

	// Check for phishing in subject
	if strings.Contains(subjectLower, "phishing") {
		event := events.NewEvent("cyberint")
		event.EventDate = eventDate

		// Extract official URL
		officialURL := common.GetNonEmptyLineAfter(body, "The legitimate and official interface can be found on the following URL:")

		// Create phishing event type with official URL
		phishing := events.NewPhishingWithOfficialURL(officialURL)
		event.EventTypes = []events.EventType{phishing}

		// Extract phishing URL
		event.URL = common.GetNonEmptyLineAfter(body, "The phishing interface can be found on the following URL:")

		results = append(results, event)
		return results, nil
	}

	// Check for Copyright in body
	if strings.Contains(body, "Copyright") {
		event := events.NewEvent("cyberint")
		event.EventDate = eventDate

		// Extract official URL
		officialURL := common.GetNonEmptyLineAfter(body, "The original material is located on my website at the following URLs:")

		// Create copyright event type
		copyright := events.NewCopyright("", "", "")
		copyright.OfficialURL = officialURL
		event.EventTypes = []events.EventType{copyright}

		// Extract infringing URL
		event.URL = common.GetNonEmptyLineAfter(body, "The infringing material is located at the following URLs:")

		results = append(results, event)
		return results, nil
	}

	// Unknown type
	return nil, common.NewNewTypeError(subjectLower)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
