package interconnect

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var loginAttackPattern = regexp.MustCompile(`(?i)attack_timestamp:\s+(?P<date>.*)\s+attack_target:\s+(?P<dst_url>.*)\s+proxy_driver_ip:\s+(?P<ip>\S+)\s+proxy_driver_port:\s+(?P<port>\d+)`)

func NewParser() *Parser {
	return &Parser{}
}

func parseDDoS(body string) (*events.Event, error) {
	event := events.NewEvent("interconnect")
	event.EventTypes = []events.EventType{events.NewDDoS()}

	eventDate := common.FindStringWithoutMarkers(body, "attack_timestamp:", "")
	event.EventDate = email.ParseDate(strings.TrimSpace(eventDate))

	portStr := common.FindStringWithoutMarkers(body, "proxy_driver_port:", "")
	portStr = strings.TrimSpace(portStr)
	if portStr != "" {
		port, err := common.ParsePort(portStr)
		if err == nil {
			event.Port = port
		}
	}

	ip := common.GetNonEmptyLineAfter(body, "Offending IP addresses:")
	if validIP := common.IsIP(ip); validIP != "" {
		event.IP = validIP
	}

	return event, nil
}

func parseBotnet(body string) (*events.Event, error) {
	event := events.NewEvent("interconnect")

	botType := common.FindStringWithoutMarkers(body, "Botnet/Malware Type:", ",")
	botType = strings.TrimSpace(botType)
	event.EventTypes = []events.EventType{events.NewBot(botType)}

	eventDate := common.FindStringWithoutMarkers(body, "Last Seen:", ")")
	event.EventDate = email.ParseDate(strings.TrimSpace(eventDate))

	ip := common.GetNonEmptyLineAfter(body, "endpoints on your network:")
	if validIP := common.IsIP(ip); validIP != "" {
		event.IP = validIP
	}

	return event, nil
}

func parseLoginAttack(body string) ([]*events.Event, error) {
	matches := loginAttackPattern.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return nil, common.NewParserError("no credential stuffing pattern found")
	}

	var results []*events.Event
	for _, match := range matches {
		// Extract named groups
		var eventDate, dstURL, ip, portStr string
		for i, name := range loginAttackPattern.SubexpNames() {
			if i > 0 && i < len(match) {
				switch name {
				case "date":
					eventDate = match[i]
				case "dst_url":
					dstURL = match[i]
				case "ip":
					ip = match[i]
				case "port":
					portStr = match[i]
				}
			}
		}

		event := events.NewEvent("interconnect")
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
		event.EventDate = email.ParseDate(eventDate)

		if validIP := common.IsIP(ip); validIP != "" {
			event.IP = validIP
		}

		if portStr != "" {
			port, err := common.ParsePort(portStr)
			if err == nil {
				event.Port = port
			}
		}

		// Add target URL as event detail
		if dstURL != "" {
			target := &events.Target{
				URL: dstURL,
			}
			event.AddEventDetail(target)
		}

		results = append(results, event)
	}

	if len(results) == 0 {
		return nil, common.NewParserError("no valid login attack events parsed")
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

	if strings.Contains(subjectLower, "ddos") {
		event, err := parseDDoS(body)
		if err != nil {
			return nil, err
		}
		return []*events.Event{event}, nil
	} else if strings.Contains(subjectLower, "botnet") {
		event, err := parseBotnet(body)
		if err != nil {
			return nil, err
		}
		return []*events.Event{event}, nil
	} else if strings.Contains(subjectLower, "credential stuffing attacks") {
		return parseLoginAttack(body)
	}

	return nil, common.NewParserError("unknown email type: " + subjectLower)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
