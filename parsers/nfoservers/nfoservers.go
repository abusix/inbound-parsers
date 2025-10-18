package nfoservers

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

var datePattern = regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}`)
var digitPattern = regexp.MustCompile(`\d+`)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// Parse processes NFOServers abuse reports
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Check sender
	fromAddr, err := common.GetFrom(serializedEmail, false)
	if err != nil || fromAddr != "ddos-response@nfoservers.com" {
		return nil, fmt.Errorf("not from expected sender")
	}

	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)
	var event *events.Event

	switch {
	case strings.HasPrefix(subjectLower, "compromised host"):
		event = parseCompromisedAndExploit(serializedEmail, body, events.NewBot(""))
	case strings.Contains(subjectLower, "exploitable chargen service"):
		event = parseCompromisedAndExploit(serializedEmail, body, events.NewOpen(common.MapServiceStrings(subjectLower)))
	case strings.Contains(subjectLower, "exploitable ntp"):
		event = parseNTP(serializedEmail, body)
	case strings.Contains(subjectLower, "exploitable memcache"):
		event = parseCompromisedAndExploit(serializedEmail, body, events.NewExploit())
	case strings.Contains(subjectLower, "exploitable ldap server"):
		event = parseCompromisedAndExploit(serializedEmail, body, events.NewOpen(common.MapServiceStrings(subjectLower)))
	case strings.Contains(subjectLower, "exploitable ssdp server"):
		event = parseCompromisedAndExploit(serializedEmail, body, events.NewOpen(common.MapServiceStrings(subjectLower)))
	case strings.Contains(subjectLower, "open snmp service"):
		event = parseCompromisedAndExploit(serializedEmail, body, events.NewOpen(common.MapServiceStrings(subjectLower)))
	case strings.Contains(subjectLower, "compromised host used for an attack") && strings.Contains(body, "part of a coordinated DDoS botnet"):
		event = parseCompromisedAndExploit(serializedEmail, body, events.NewDDoS())
	case strings.Contains(subjectLower, "open recursive resolver"):
		event = parseCompromisedAndExploit(serializedEmail, body, events.NewOpen(common.MapServiceStrings(subjectLower)))
	case strings.Contains(subjectLower, "reflection/amplification"):
		event = parseReflectionAmplification(body, serializedEmail)
	default:
		return nil, fmt.Errorf("unknown subject type: %s", subjectLower)
	}

	if event == nil {
		return nil, fmt.Errorf("no event created")
	}

	return []*events.Event{event}, nil
}

func parseCompromisedAndExploit(serializedEmail *email.SerializedEmail, body string, eventType events.EventType) *events.Event {
	event := events.NewEvent("nfoservers")
	event.EventTypes = []events.EventType{eventType}

	// IP from subject
	subject, _ := common.GetSubject(serializedEmail, false)
	event.IP = subject

	// Event date from email headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		if parsedDate := email.ParseDate(dateHeader[0]); parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	var targetIPCensored string
	var date string
	var octet string
	var targetIP string
	var targetPort string
	var sourcePort int

	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)

		// Extract source port
		if sourcePort == 0 && strings.Contains(line, "on port") {
			portStr := common.FindStringWithoutMarkers(line, "on port ", " ")
			if port, err := strconv.Atoi(portStr); err == nil {
				sourcePort = port
			}
		}
		if sourcePort == 0 && strings.Contains(line, "UDP port") {
			matches := digitPattern.FindAllString(line, -1)
			if len(matches) > 0 {
				if port, err := strconv.Atoi(matches[0]); err == nil {
					sourcePort = port
				}
			}
		}

		// Extract target IP (censored)
		if strings.Contains(line, " > ") {
			parts := strings.Split(line, " > ")
			if len(parts) >= 2 {
				targetIPPart := parts[len(parts)-1]
				colonParts := strings.Split(targetIPPart, ": ")
				if len(colonParts) > 0 {
					targetIPCensored = colonParts[0]
				}
			}
		}

		// Extract destination IP
		if strings.Contains(line, "destination IP address") {
			if ip := common.ExtractOneIP(line); ip != "" {
				targetIP = ip
			}
		}

		// Extract date
		if datePattern.MatchString(line) && date == "" {
			if parsedDate := email.ParseDate(line); parsedDate != nil {
				date = line
				event.EventDate = parsedDate
			}
		}

		// Extract octet
		if strings.HasPrefix(line, "(The final octet") {
			parts := strings.Split(line, " ")
			if len(parts) > 0 {
				relevant := parts[len(parts)-1]
				octetPart := strings.TrimSuffix(relevant, ".")
				octet = strings.Trim(octetPart, `"`)
			}
		}
	}

	// Reconstruct target IP if censored
	if targetIP == "" && targetIPCensored != "" && octet != "" {
		targetIPUncensored := strings.ReplaceAll(targetIPCensored, "x", octet)
		lastDotIdx := strings.LastIndex(targetIPUncensored, ".")
		if lastDotIdx != -1 {
			targetIP = targetIPUncensored[:lastDotIdx]
			targetPort = targetIPUncensored[lastDotIdx+1:]
		}
	}

	// Add target details
	if targetIP != "" || targetPort != "" {
		target := &events.Target{
			IP:   targetIP,
			Port: targetPort,
		}
		event.EventDetails = append(event.EventDetails, target)
	}

	if sourcePort != 0 {
		event.Port = sourcePort
	}

	return event
}

func parseNTP(serializedEmail *email.SerializedEmail, body string) *events.Event {
	event := events.NewEvent("nfoservers")
	event.EventTypes = []events.EventType{events.NewDDoS()}

	// IP from subject
	subject, _ := common.GetSubject(serializedEmail, false)
	event.IP = subject

	// Event date from email headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		if parsedDate := email.ParseDate(dateHeader[0]); parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, "UDP port ") {
			parts := strings.Split(line, "UDP port ")
			if len(parts) >= 2 {
				portPart := parts[1]
				commaParts := strings.Split(portPart, ",")
				if len(commaParts) > 0 {
					portStr := strings.TrimSpace(commaParts[0])
					if port, err := strconv.Atoi(portStr); err == nil {
						event.Port = port
						break
					}
				}
			}
		}
	}

	return event
}

func parseReflectionAmplification(body string, serializedEmail *email.SerializedEmail) *events.Event {
	bodyLower := strings.ToLower(body)

	ip := common.FindStringWithoutMarkers(bodyLower, "ip address ", " ")
	portStr := common.FindStringWithoutMarkers(bodyLower, ip+".", " ")
	octet := strings.TrimSpace(strings.Trim(common.FindStringWithoutMarkers(bodyLower, "value of that octet is", ""), `"). `))
	targetCensored := common.FindStringWithoutMarkers(bodyLower, ip+"."+portStr+" >", ":")
	target := strings.ReplaceAll(targetCensored, "x", octet)

	targetParts := strings.Split(target, ".")
	var targetIP, targetPort string
	if len(targetParts) >= 5 {
		targetIP = strings.Join(targetParts[:4], ".")
		targetPort = targetParts[4]
	}

	event := events.NewEvent("nfoservers")
	event.EventTypes = []events.EventType{events.NewDDoS()}

	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		if parsedDate := email.ParseDate(dateHeader[0]); parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	event.IP = ip
	if port, err := strconv.Atoi(portStr); err == nil {
		event.Port = port
	}

	if targetIP != "" || targetPort != "" {
		targetDetail := &events.Target{
			IP:   targetIP,
			Port: targetPort,
		}
		event.EventDetails = append(event.EventDetails, targetDetail)
	}

	return event
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
