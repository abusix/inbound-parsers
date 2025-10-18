package cscglobal

import (
	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"regexp"
	"strings"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	// Strip HTML and convert to lower
	re := regexp.MustCompile(`<[^>]*>`)
	bodyClean := re.ReplaceAllString(body, " ")
	bodyLower := strings.ToLower(strings.ReplaceAll(bodyClean, "at :", "at:"))

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	event := events.NewEvent("cscglobal")

	// Extract IP from subject or body
	ip := common.ExtractOneIP(subject)
	if ip == "" && strings.Contains(bodyLower, "email header") {
		if strings.Contains(bodyLower, "x-originating-ip: ") {
			ip = common.ExtractOneIP(common.FindStringWithoutMarkers(bodyLower, "x-originating-ip:", ""))
		}
		if ip == "" {
			ip = common.ExtractOneIP(common.FindStringWithoutMarkers(bodyLower, "ip address", ""))
		}
	}

	// Extract URL from subject
	urlMatch := regexp.MustCompile(`(http\S+)`).FindString(subjectLower)
	url := urlMatch
	if url == "" {
		url = common.FindStringWithoutMarkers(bodyLower, "can be found at:", "")
	}
	if url == "" {
		url = common.FindStringWithoutMarkers(bodyLower, "the website in question is", "")
	}

	// Determine event type
	if strings.Contains(subjectLower, "phishing") || strings.Contains(subjectLower, " unauthorized job post") {
		event.EventTypes = []events.EventType{events.NewPhishing()}
	} else if strings.Contains(subjectLower, "copyright infringement") || strings.Contains(subjectLower, "dmca") {
		event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}
	} else if strings.Contains(subjectLower, "trademark infringement") || strings.Contains(subjectLower, "assistance with an infringing") {
		event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}
	} else if strings.Contains(subjectLower, "web site involved in fraudulent scheme") ||
		strings.Contains(subjectLower, "email account used in fraudulent scheme") ||
		strings.Contains(subjectLower, "malicious scheme") ||
		strings.Contains(subjectLower, "fraud") {
		event.EventTypes = []events.EventType{events.NewFraud()}
	} else if strings.Contains(subjectLower, "adult content") || strings.Contains(subjectLower, "counterfeit activity") {
		event.EventTypes = []events.EventType{events.NewIllegalAdvertisement()}
	} else if strings.Contains(bodyLower, "trademark") {
		event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}
	} else if strings.Contains(subjectLower, "redirection activity") ||
		strings.Contains(subjectLower, "impersonating") ||
		strings.Contains(subjectLower, "impersonation") {
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
	} else {
		return nil, common.NewNewTypeError(subject)
	}

	event.IP = ip
	event.URL = url

	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
