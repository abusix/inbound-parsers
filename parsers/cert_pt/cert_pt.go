package cert_pt

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
	body, _ := common.GetBody(serializedEmail, true)
	bodyLower := strings.ToLower(body)

	// Extract abuse type
	var abuseType string
	if extracted := common.FindStringWithoutMarkers(bodyLower, "incident classification:", ""); extracted != "" {
		abuseType = strings.TrimSpace(extracted)
	} else {
		abuseType = strings.TrimSpace(common.GetNonEmptyLineAfter(bodyLower, "incident classification:"))
	}

	event := events.NewEvent("cert_pt")

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Map abuse type to event type
	switch abuseType {
	case "phishing":
		event.EventTypes = []events.EventType{events.NewPhishing()}
	case "malware distribution":
		event.EventTypes = []events.EventType{events.NewMalwareHosting()}
	case "exploitation of known vulnerabilities":
		event.EventTypes = []events.EventType{events.NewWebHack()}
	case "vulnerability exploitation":
		event.EventTypes = []events.EventType{events.NewWebHack()}
	case "login attempts":
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	case "distributed denial of service":
		event.EventTypes = []events.EventType{events.NewDDoS()}
	case "unauthorised use of third party name":
		event.EventTypes = []events.EventType{events.NewFraud()}
	default:
		return nil, common.NewNewTypeError("New abuse type in cert_pt: " + abuseType)
	}

	// Try to extract IP address
	ipPattern := regexp.MustCompile(`(ip\(s\):|ip:)\s+(?P<ip>(\d|\.)+)`)
	if match := ipPattern.FindStringSubmatch(bodyLower); match != nil {
		// Find the named group "ip"
		for i, name := range ipPattern.SubexpNames() {
			if name == "ip" && i < len(match) {
				event.IP = match[i]
				break
			}
		}
	} else if strings.Contains(bodyLower, "ips:") {
		// Multiple IPs - set first URL if possible
		if urlLine := common.GetNonEmptyLineAfter(bodyLower, "urls:"); urlLine != "" {
			event.URL = urlLine
		}

		// Extract block of IPs
		ipBlock := common.GetBlockAfterWithStop(strings.ReplaceAll(bodyLower, "ips:", "ips:\n\n"), "ips:", "")
		var result []*events.Event
		for _, ip := range ipBlock {
			newEvent := *event // copy event
			newEvent.IP = ip
			result = append(result, &newEvent)
		}
		return result, nil
	}

	// Try to extract URL
	urlPattern := regexp.MustCompile(`(url\(s\):|url:)\s+(?P<url>(hxxp|http)\S+)`)
	if match := urlPattern.FindStringSubmatch(bodyLower); match != nil {
		// Find the named group "url"
		for i, name := range urlPattern.SubexpNames() {
			if name == "url" && i < len(match) {
				event.URL = match[i]
				break
			}
		}
	} else if strings.Contains(bodyLower, "urls:") {
		// Multiple URLs
		urlBlock := common.GetBlockAfterWithStop(strings.ReplaceAll(bodyLower, "urls:", "urls:\n\n"), "urls:", "")
		var result []*events.Event
		for _, url := range urlBlock {
			newEvent := *event // copy event
			newEvent.URL = url
			result = append(result, &newEvent)
		}
		return result, nil
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
