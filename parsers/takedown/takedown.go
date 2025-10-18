package takedown

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
	// Get body with error if empty
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Get subject
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Create event
	event := events.NewEvent("takedown")

	// Set event date from email headers
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Check subject to determine report type
	subjectLower := strings.ToLower(subject)
	if strings.Contains(subjectLower, "dmca violation") {
		// Extract original URL
		originalURL := common.GetNonEmptyLineAfter(body, "original copyrighted material in question can be found at the addresses below:")

		// Extract copyright owner
		originalOwner := common.GetNonEmptyLineAfter(body, "Copyright Owner:")

		// Create Copyright event type
		copyright := events.NewCopyright("", originalOwner, "")
		copyright.OfficialURL = originalURL
		event.EventTypes = []events.EventType{copyright}

		// Extract infringing URL
		event.URL = common.GetNonEmptyLineAfter(body, "infringing materials may be found at:")

		return []*events.Event{event}, nil
	}

	// If subject doesn't match known types, return error
	return nil, fmt.Errorf("new type error: unknown subject type: %s", subjectLower)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
