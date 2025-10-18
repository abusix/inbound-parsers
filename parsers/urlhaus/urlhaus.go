package urlhaus

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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)

	if strings.Contains(subjectLower, "malware distribution") {
		return parseMalwareDistribution(serializedEmail, body, subject)
	} else if strings.Contains(subjectLower, "active botnet") {
		return parseBotnet(body)
	}

	return nil, common.NewNewTypeError(subject)
}

func parseMalwareDistribution(serializedEmail *email.SerializedEmail, body, subject string) ([]*events.Event, error) {
	event := events.NewEvent("urlhaus")
	event.EventTypes = []events.EventType{events.NewMalwareHosting()}

	// Get event date from email headers
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventDate := email.ParseDate(dateHeaders[0])
			event.EventDate = eventDate
		}
	}

	// Set IP from subject
	event.IP = subject

	// Parse key-value pairs from body
	kvPairs := common.OneLineColonKeyValueGenerator(body)

	var asn, asName string

	for key, values := range kvPairs {
		if len(values) == 0 {
			continue
		}
		value := values[0]
		keyLower := strings.ToLower(key)

		switch keyLower {
		case "as number":
			asn = value
			event.AddEventDetail(&events.ASN{ASN: value})
		case "as name":
			asName = value
		case "url":
			event.URL = common.CleanURL(value)
		case "proof":
			evidence := &events.Evidence{}
			evidence.AddEvidence(events.UrlStore{
				Description: "proof",
				URL:         value,
			})
			event.AddEventDetail(evidence)
		}
	}

	// Add combined ASN detail with both asn and as_name
	if asn != "" || asName != "" {
		event.AddEventDetail(&events.ASN{
			ASN:    asn,
			ASName: asName,
		})
	}

	return []*events.Event{event}, nil
}

func parseBotnet(body string) ([]*events.Event, error) {
	event := events.NewEvent("urlhaus")

	// Extract values from body
	ip := strings.TrimSpace(common.FindStringWithoutMarkers(body, "IP address:", ""))
	port := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Port:", ""))
	malware := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Malware:", ""))
	eventDate := strings.TrimSpace(common.FindStringWithoutMarkers(body, "First seen:", ""))
	proof := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Proof:", ""))

	event.IP = ip

	// Parse port
	if port != "" {
		if portNum, err := common.ParsePort(port); err == nil {
			event.Port = portNum
		}
	}

	// Set bot type
	event.EventTypes = []events.EventType{events.NewBot(malware)}

	// Parse event date
	if eventDate != "" {
		parsedDate := email.ParseDate(eventDate)
		event.EventDate = parsedDate
	}

	// Add proof as evidence
	if proof != "" {
		evidence := &events.Evidence{}
		evidence.AddEvidence(events.UrlStore{
			Description: "",
			URL:         proof,
		})
		event.AddEventDetail(evidence)
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
