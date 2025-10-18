package irs

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

var (
	ipPattern        = regexp.MustCompile(`IP:\s*([^\n]+)`)
	urlPattern       = regexp.MustCompile(`URL:\s*[^h.]*(\S+)`)
	urlPatternFraud  = regexp.MustCompile(`Domain Name:\s*(\S+)`)
	asnPattern       = regexp.MustCompile(`ASN:\s*(\d+)`)
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get body and subject with throws=True to match Python behavior
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Create event template
	eventTemplate := events.NewEvent("irs")

	// Set event_date from headers['date'][0]
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventTemplate.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	subjectLower := strings.ToLower(subject)

	if strings.Contains(subjectLower, "phishing") {
		return p.parsePhishing(body, eventTemplate)
	} else if strings.Contains(subjectLower, "please de-register") {
		return p.parseFraud(body, eventTemplate)
	}

	return nil, common.NewNewTypeError(subject)
}

func (p *Parser) parseFraud(body string, event *events.Event) ([]*events.Event, error) {
	event.EventTypes = []events.EventType{events.NewFraud()}

	if urlMatch := urlPatternFraud.FindStringSubmatch(body); urlMatch != nil {
		event.URL = urlMatch[1]
		return []*events.Event{event}, nil
	}

	return nil, nil
}

func (p *Parser) parsePhishing(body string, event *events.Event) ([]*events.Event, error) {
	// Extract URL
	if urlMatch := urlPattern.FindStringSubmatch(body); urlMatch != nil {
		event.URL = urlMatch[1]
	}

	// Extract ASN
	if asnMatch := asnPattern.FindStringSubmatch(body); asnMatch != nil {
		asn := &events.ASN{
			ASN: strings.TrimSpace(asnMatch[1]),
		}
		event.AddEventDetail(asn)
	}

	// Extract IP
	if ipMatch := ipPattern.FindStringSubmatch(body); ipMatch != nil {
		ipStr := strings.TrimSpace(strings.ReplaceAll(ipMatch[1], "[.]", "."))
		event.IP = ipStr
	}

	// Only create event if we have IP or URL
	if event.IP != "" || event.URL != "" {
		// Create Phishing event type with phishing_url set to event.url
		phishing := events.NewPhishing()
		phishing.PhishingTarget = event.URL
		event.EventTypes = []events.EventType{phishing}
		return []*events.Event{event}, nil
	}

	return nil, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
