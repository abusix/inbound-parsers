package b_monitor

import (
	"regexp"
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

	// Extract external ID from subject: [Notice ID *...*]
	externalID := common.FindStringWithoutMarkers(subject, "[Notice ID *", "*")

	// Determine parsing mode based on body content
	if strings.Contains(body, "We would like to bring to your notice") {
		return parseCopyright(serializedEmail, body, subject, externalID)
	}
	return parseSingleURLCopyright(serializedEmail, body, subject, externalID)
}

// parseCopyright handles multi-URL copyright reports
func parseCopyright(serializedEmail *email.SerializedEmail, body, subject, externalID string) ([]*events.Event, error) {
	var evts []*events.Event

	// Extract ASN from subject: " AS<number> "
	asn := common.FindStringWithoutMarkers(subject, " AS", " ")

	// Extract copyright owner from body
	ownerRaw := common.FindStringWithoutMarkers(body, "are an authorized representative of", "")
	owner := strings.TrimSpace(strings.Split(ownerRaw, "(")[0])

	// Extract IP from subject
	ip := common.ExtractOneIP(subject)

	// Extract URLs - get block after marker
	urls := common.GetBlockAfterWithStop(body, "We would like to bring to your notice", "")

	// Get event date from headers
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	// Create an event for each URL
	for _, url := range urls {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}

		event := events.NewEvent("b_monitor")
		event.EventTypes = []events.EventType{events.NewCopyright("", owner, "")}
		event.URL = url
		event.IP = ip
		event.EventDate = eventDate

		// Add ASN detail if present
		if asn != "" {
			event.AddEventDetail(&events.ASN{ASN: asn})
		}

		// Add external ID if present
		if externalID != "" {
			event.AddEventDetail(&events.ExternalID{ID: externalID})
		}

		evts = append(evts, event)
	}

	if len(evts) == 0 {
		return nil, &common.ParserError{Message: "no event created"}
	}

	return evts, nil
}

// parseSingleURLCopyright handles single-URL copyright reports
func parseSingleURLCopyright(serializedEmail *email.SerializedEmail, body, subject, externalID string) ([]*events.Event, error) {
	// Extract copyright owner from body using regex: (')owner(')
	ownerRegex := regexp.MustCompile(`\(\'(.*?)\'\)`)
	var owner string
	if matches := ownerRegex.FindStringSubmatch(body); len(matches) > 1 {
		owner = matches[1]
	}

	// Extract URL and IP from subject using regex: "url (ip)"
	urlIPRegex := regexp.MustCompile(`([^\s]* )\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
	matches := urlIPRegex.FindStringSubmatch(subject)
	if len(matches) < 3 {
		return nil, &common.ParserError{Message: "could not extract URL and IP from subject"}
	}

	url := strings.TrimSpace(matches[1])
	ip := matches[2]

	// Get event date from headers
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	event := events.NewEvent("b_monitor")
	event.EventTypes = []events.EventType{events.NewCopyright("", owner, "")}
	event.URL = url
	event.IP = ip
	event.EventDate = eventDate

	// Add external ID if present
	if externalID != "" {
		event.AddEventDetail(&events.ExternalID{ID: externalID})
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
