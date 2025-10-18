package csirt_divd

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
	subject, _ := common.GetSubject(serializedEmail, false)
	body, _ := common.GetBody(serializedEmail, false)
	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)

	event := events.NewEvent("csirt_divd")

	// Determine event type
	malware := common.FindStringWithoutMarkers(bodyLower, "called \"", "\"")
	if malware != "" {
		event.EventTypes = []events.EventType{events.NewMalware(malware)}
	} else if cveMatch := regexp.MustCompile(`(CVE-\d{4}-\d{4,7})`).FindString(body); cveMatch != "" {
		event.EventTypes = []events.EventType{events.NewCVE(cveMatch, "", "")}
	} else if strings.Contains(subjectLower, "greynoise ukraine only list") {
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
	} else {
		// Default to Open service
		event.EventTypes = []events.EventType{events.NewOpen(common.MapServiceStrings(subjectLower))}
	}

	// Extract IP from subject first
	ip := common.ExtractOneIP(subject)
	if ip == "" {
		// Try to find IP markers in body
		ipMarkers := []string{"ip address(es):", "host:", "ip address:", "ip:"}
		for _, marker := range ipMarkers {
			if strings.Contains(bodyLower, marker) {
				ip = common.ExtractOneIP(common.FindStringWithoutMarkers(bodyLower, marker, ""))
				if ip != "" {
					break
				}
			}
		}
	}

	if ip == "" {
		// Try URL marker
		url := common.FindStringWithoutMarkers(bodyLower, "url:", "")
		if url == "" {
			// Try Host/IP or Hostname markers
			for _, marker := range []string{"host/ip:", "hostname:"} {
				url = strings.TrimSpace(common.FindStringWithoutMarkers(body, marker, ""))
				if url != "" {
					break
				}
			}
		}
		event.URL = url
	}

	event.IP = ip

	// Try to extract port
	portStr := common.FindStringWithoutMarkers(bodyLower, "port:", "")
	portClean := regexp.MustCompile(`[^0-9]`).ReplaceAllString(portStr, "")
	if portClean != "" {
		if port, err := common.ParsePort(portClean); err == nil {
			event.Port = port
		}
	}

	// Set event date - would need datetime parser for full implementation
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
