package bytescare

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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)

	if strings.Contains(subjectLower, "copyright") {
		return parseCopyright(body, serializedEmail)
	}

	return nil, common.NewNewTypeError(subjectLower)
}

func parseCopyright(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	bodyLower := strings.ToLower(body)

	// Get infringing URLs
	infringingLinks := common.GetContinuousLinesUntilEmptyLine(bodyLower, "infringing urls:")
	if len(infringingLinks) == 0 {
		return nil, common.NewParserError("infringing urls not found")
	}

	// Extract copyright owner
	var owner string
	ownerText := common.FindStringWithoutMarkers(bodyLower, "on behalf of our client", "")
	if ownerText != "" {
		owner = strings.TrimSpace(ownerText)
	}

	// Get event date from email headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	// Create events for each infringing URL
	var result []*events.Event

	for _, url := range infringingLinks {
		event := events.NewEvent("bytescare")
		event.URL = strings.TrimSpace(url)
		event.EventDate = eventDate
		event.EventTypes = []events.EventType{
			events.NewCopyright("", owner, ""),
		}

		result = append(result, event)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
