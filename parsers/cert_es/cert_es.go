package cert_es

import (
	"regexp"
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
	subject, _ := common.GetSubject(serializedEmail, false)

	var externalID, ip, url, date, targetIP string

	// Try multiple regex patterns to extract data from subject and body
	if matches := regexp.MustCompile(`#(.*)\]\D*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*\[(.*)\]`).FindStringSubmatch(subject); matches != nil {
		externalID = matches[1]
		ip = matches[2]
		url = matches[3]
	} else if matches := regexp.MustCompile(`(\d{4}-\d{2}-\d{2} \d{2}:\d{2}),\d{4}-\d{2}-\d{2} \d{2}:\d{2},(\S+),\S+,\S+,(\S+)`).FindStringSubmatch(body); matches != nil {
		date = matches[1]
		targetIP = matches[2]
		ip = matches[3]
	} else if matches := regexp.MustCompile(`#(.*)\]\D*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`).FindStringSubmatch(subject); matches != nil {
		externalID = matches[1]
		ip = matches[2]
	} else if matches := regexp.MustCompile(`#(.*)\]`).FindStringSubmatch(subject); matches != nil {
		externalID = matches[1]
	} else {
		return nil, common.NewParserError("adapt the parser")
	}

	// Try to extract IP if not found yet
	if common.IsIP(ip) == "" {
		ip = common.ExtractOneIP(common.GetNonEmptyLineAfter(body, "hosted at"))
	}
	if common.IsIP(ip) == "" {
		ip = common.ExtractOneIP(common.GetNonEmptyLineAfter(body, "following IP"))
	}
	if common.IsIP(ip) == "" {
		ip = common.ExtractOneIP(common.GetNonEmptyLineAfter(body, "siguiente dirección IP"))
	}
	if common.IsIP(ip) == "" {
		ip = common.ExtractOneIP(common.FindStringWithoutMarkers(body, "IP", ""))
	}
	if common.IsIP(ip) == "" {
		ip = common.ExtractOneIP(common.GetNonEmptyLineAfter(body, "Resolves to"))
	}
	if common.IsIP(ip) == "" {
		ip = common.ExtractOneIP(common.GetNonEmptyLineAfter(body, "resolver:"))
	}
	if common.IsIP(ip) == "" {
		ip = common.ExtractOneIP(common.GetNonEmptyLineAfter(body, "siguientes direcciones IP:"))
	}

	// Try to extract URL if not found yet
	if !common.IsURL(url) {
		url = common.GetNonEmptyLineAfter(body, "following URL")
	}
	if !common.IsURL(url) {
		url = common.FindStringWithoutMarkers(body, "website at ", " ")
	}
	if !common.IsURL(url) {
		url = common.GetNonEmptyLineAfter(body, "actions to resolve this incident")
	}

	event := events.NewEvent("cert_es")

	// Determine event type based on subject and body content
	subjectLower := strings.ToLower(subject)
	patterns := []string{"malicious", "fraud", "falsa", "scam", "malicioso", "falso", "fake", "maious"}

	if strings.Contains(subjectLower, "phishing") || strings.Contains(subjectLower, "redirect") || strings.Contains(body, "HtmlPhisher") {
		event.EventTypes = []events.EventType{events.NewPhishing()}
	} else if strings.Contains(subjectLower, "defacement") {
		event.EventTypes = []events.EventType{events.NewDefacement()}
	} else if strings.Contains(subjectLower, "expuesto") {
		service := common.FindStringWithoutMarkers(subjectLower, "servicio", "expuesto")
		event.EventTypes = []events.EventType{events.NewOpen(service)}
	} else if strings.Contains(subjectLower, "malware") || strings.Contains(body, "malware") {
		event.EventTypes = []events.EventType{events.NewMalware("")}
	} else if strings.Contains(subjectLower, "compromised website") || strings.Contains(body, "compromised") {
		event.EventTypes = []events.EventType{events.NewCompromisedWebsite("")}
	} else if containsAny(subjectLower, patterns) || strings.Contains(body, "fraudulent service") {
		event.EventTypes = []events.EventType{events.NewFraud()}
	} else {
		return nil, common.NewNewTypeError(subject)
	}

	// Add target IP if present
	if targetIP != "" {
		event.AddEventDetail(&events.Target{IP: targetIP})
	}

	// Set event date
	if date == "" {
		if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
			event.EventDate = email.ParseDate(dateHeader[0])
		}
	} else {
		event.EventDate = email.ParseDate(date)
	}

	event.IP = ip
	event.URL = common.CleanURL(url)
	event.AddEventDetail(&events.ExternalID{ID: externalID})

	return []*events.Event{event}, nil
}

// containsAny checks if any of the patterns exist in the text
func containsAny(text string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(text, pattern) {
			return true
		}
	}
	return false
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
