package ncsc_fi

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

// NewTypeError is raised when the event type cannot be determined
type NewTypeError struct {
	Subject string
}

func (e *NewTypeError) Error() string {
	return fmt.Sprintf("unknown event type from subject: %s", e.Subject)
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

	event := events.NewEvent("ncsc_fi")

	// Determine event type from subject
	subjectLower := strings.ToLower(subject)

	if strings.Contains(subjectLower, "phishing") {
		event.EventTypes = []events.EventType{events.NewPhishing()}
	} else if strings.Contains(subjectLower, "malware") {
		event.EventTypes = []events.EventType{events.NewMalware("")}
	} else if strings.Contains(subjectLower, "spam") {
		event.EventTypes = []events.EventType{events.NewSpam()}
	} else if strings.Contains(subjectLower, "webshell") {
		event.EventTypes = []events.EventType{events.NewCompromisedServer()}
	} else if strings.Contains(subjectLower, "malicious redirection") || strings.Contains(body, "Malicious site") {
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
	} else if strings.Contains(subjectLower, "botnet") {
		event.EventTypes = []events.EventType{events.NewBot("")}
	} else {
		return nil, &NewTypeError{Subject: subjectLower}
	}

	// Extract fields from body
	externalID := common.FindStringWithoutMarkers(body, "NCSC-FI case:", "")
	externalID = strings.TrimSpace(externalID)
	if externalID != "" {
		event.AddEventDetail(&events.ExternalID{ID: externalID})
	}

	event.IP = common.FindStringWithoutMarkers(body, "Host ip:", "")

	// URL is optional
	url := common.FindStringWithoutMarkers(body, "Site:", "")
	if url != "" {
		event.URL = url
	}

	eventDate := common.FindStringWithoutMarkers(body, "Timestamp:", "")
	eventDate = strings.TrimSpace(eventDate)
	if eventDate != "" {
		parsedDate := email.ParseDate(eventDate)
		event.EventDate = parsedDate
	}

	asn := common.FindStringWithoutMarkers(body, "ASN:", "")
	asn = strings.TrimSpace(asn)
	if asn != "" {
		event.AddEventDetail(&events.ASN{ASN: asn})
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
