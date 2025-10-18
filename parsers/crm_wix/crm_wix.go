package crm_wix

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// stripHTML removes HTML tags from a string
func stripHTML(html string) string {
	re := regexp.MustCompile(`<[^>]*>`)
	text := re.ReplaceAllString(html, " ")
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")
	return strings.TrimSpace(text)
}

func parseAbuseReportForm(attachment string, event *events.Event) ([]*events.Event, error) {
	attachmentLower := strings.ToLower(stripHTML(attachment))

	ip := common.FindStringWithoutMarkers(attachmentLower, "ip address: ", "complaint type:")
	eventType := common.FindStringWithoutMarkers(attachmentLower, "complaint type: ", "additional information")
	information := ""
	if parts := strings.Split(attachmentLower, "additional information  (1000 symbols):"); len(parts) > 1 {
		information = parts[1]
	}

	// Determine event type
	checkType := func(keywords ...string) bool {
		for _, keyword := range keywords {
			if strings.Contains(eventType, keyword) || strings.Contains(information, keyword) {
				return true
			}
		}
		return false
	}

	if checkType("copyright") {
		event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}
	} else if checkType("phishing") {
		event.EventTypes = []events.EventType{events.NewPhishing()}
	} else if checkType("ddos") {
		event.EventTypes = []events.EventType{events.NewDDoS()}
	} else if checkType("trademark") {
		event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}
	} else if checkType("brute force") {
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	} else if checkType("child porn") {
		event.EventTypes = []events.EventType{events.NewChildAbuse()}
	} else if checkType("fraud") {
		event.EventTypes = []events.EventType{events.NewFraud()}
	} else if checkType("malware") {
		event.EventTypes = []events.EventType{events.NewMalware("")}
	} else if checkType("malicious") {
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
	} else {
		return nil, common.NewNewTypeError(eventType)
	}

	// Try to set IP
	if common.IsIP(ip) != "" {
		event.IP = ip
	} else {
		infoIP := strings.ReplaceAll(information, "[.]", ".")
		if common.IsIP(infoIP) != "" {
			event.IP = infoIP
		} else {
			return nil, nil
		}
	}

	return []*events.Event{event}, nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	event := events.NewEvent("crm_wix")

	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
	}

	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	if strings.Contains(body, "Your Report Abuse form got a new submission") {
		attachment, err := common.FindFirstAttachmentWithMimeType(serializedEmail, "text/html")
		if err == nil && attachment != "" {
			return parseAbuseReportForm(attachment, event)
		}
	}

	return nil, common.NewNewTypeError(subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
