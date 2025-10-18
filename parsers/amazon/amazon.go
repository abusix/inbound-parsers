package amazon

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	botnetPattern = regexp.MustCompile(`(?i)((?P<ip>\[?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\]?)).*(Malware Type:(?P<malware_type>.*))(Last Seen: (?P<date>[^)]*))`)
	ddosPattern   = regexp.MustCompile(`attack_timestamp: (.*?)\nattack_target: (.*?)\nproxy_driver_ip: (.*?)\nproxy_driver_port: (.*?)\nabused_proxy_ip: (.*?)\nabused_proxy_port: (.*)`)
)

func NewParser() *Parser {
	return &Parser{}
}

func parseBotnetAttack(body string) ([]*events.Event, error) {
	match := botnetPattern.FindStringSubmatch(body)
	if len(match) == 0 {
		return nil, common.NewParserError("no botnet pattern match found")
	}

	var ip, malwareType, eventDate string
	for i, name := range botnetPattern.SubexpNames() {
		if i < len(match) {
			switch name {
			case "ip":
				ip = match[i]
			case "malware_type":
				malwareType = match[i]
			case "date":
				eventDate = match[i]
			}
		}
	}

	event := events.NewEvent("amazon")
	event.IP = ip
	event.EventDate = email.ParseDate(eventDate)
	malwareType = strings.TrimSpace(strings.ReplaceAll(malwareType, ",", ""))
	event.EventTypes = []events.EventType{events.NewMalware(malwareType)}

	return []*events.Event{event}, nil
}

func parseDDoS(body string) ([]*events.Event, error) {
	matches := ddosPattern.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return nil, common.NewParserError("no ddos pattern match found")
	}

	var results []*events.Event
	for _, match := range matches {
		if len(match) != 7 {
			continue
		}

		// Strip carriage returns from all elements
		eventInfo := make([]string, len(match)-1)
		for i := 1; i < len(match); i++ {
			eventInfo[i-1] = strings.TrimRight(match[i], "\r")
		}

		if len(eventInfo) == 6 {
			event := events.NewEvent("amazon")
			event.EventDate = email.ParseDate(eventInfo[0])
			event.IP = eventInfo[2]

			// Add target details
			target := &events.Target{
				IP:   eventInfo[4],
				Port: eventInfo[5],
			}
			event.AddEventDetail(target)

			// Add attack target information as event detail
			event.AddEventDetailSimple("requests", eventInfo[1])

			event.EventTypes = []events.EventType{events.NewDDoS()}
			results = append(results, event)
		}
	}

	if len(results) == 0 {
		return nil, common.NewParserError("no valid ddos events parsed")
	}

	return results, nil
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

	if strings.Contains(subjectLower, "botnet") {
		return parseBotnetAttack(body)
	} else if strings.Contains(subjectLower, "ddos") {
		return parseDDoS(body)
	}

	return nil, common.NewParserError("unknown email type: " + subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
