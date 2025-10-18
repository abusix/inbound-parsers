package redfish

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	ipPattern      = regexp.MustCompile(`(?i)(src=)(?P<src_ip>\[?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\]?)`)
	servicePattern = regexp.MustCompile(`(?i)(?P<service>.*)( probes)`)
)

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	event := events.NewEvent("redfish")

	// Get email body
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		body = ""
	}

	// Get subject
	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, common.NewParserError("no subject found")
	}
	subjectLower := strings.ToLower(subject)

	// Get event date from headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		event.EventDate = email.ParseDate(dateHeader[0])
	}

	// Determine event type based on subject
	if strings.Contains(subjectLower, "ssh probes") || strings.Contains(subjectLower, "http proxy probes") {
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
		// Try to extract IP from body
		if matches := ipPattern.FindStringSubmatch(body); len(matches) > 0 {
			// Extract the named group src_ip
			for i, name := range ipPattern.SubexpNames() {
				if name == "src_ip" && i < len(matches) {
					ip := common.ExtractOneIP(matches[i])
					if ip != "" {
						event.IP = ip
					}
					break
				}
			}
		}
	} else if strings.Contains(subjectLower, "port scan") {
		event.EventTypes = []events.EventType{events.NewPortScan()}
	} else if strings.Contains(subjectLower, "https vulnerability") || strings.Contains(subjectLower, "http vulnerability") {
		event.EventTypes = []events.EventType{events.NewOpen(common.MapServiceStrings("http"))}
	} else if strings.Contains(subjectLower, "spam") {
		event.EventTypes = []events.EventType{events.NewSpam()}
	} else if strings.Contains(subjectLower, "auth attack") || strings.Contains(subjectLower, "smtp abuse") {
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	} else if strings.Contains(subjectLower, "phishing") {
		event.EventTypes = []events.EventType{events.NewPhishing()}
	} else if strings.Contains(subjectLower, "spoofing") {
		event.EventTypes = []events.EventType{events.NewIPSpoof("", "", false, "")}
	} else if strings.Contains(subjectLower, "extortion") {
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
	} else if strings.Contains(subjectLower, "probes") {
		// Extract service name from subject
		if matches := servicePattern.FindStringSubmatch(subjectLower); len(matches) > 0 {
			for i, name := range servicePattern.SubexpNames() {
				if name == "service" && i < len(matches) {
					service := strings.TrimSpace(matches[i])
					event.EventTypes = []events.EventType{events.NewOpen(service)}
					break
				}
			}
		}
	} else {
		return nil, common.NewNewTypeError(subject)
	}

	// If no IP was found, try to extract from subject
	if event.IP == "" {
		event.IP = common.ExtractOneIP(subject)
		if event.IP == "" {
			return nil, common.NewParserError("Unable to get IP")
		}
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
