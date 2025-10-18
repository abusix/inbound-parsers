package csa

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

// checkMarkers checks if any markers are in body or subject
func checkMarkers(body, subject string, markers []string) bool {
	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)
	for _, marker := range markers {
		if strings.Contains(bodyLower, marker) || strings.Contains(subjectLower, marker) {
			return true
		}
	}
	return false
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	event := events.NewEvent("csa")

	// Simplified implementation - handles basic text format
	// Full implementation would need CSV parsing, HTML table parsing, etc.

	// Determine event type based on subject/body markers
	if checkMarkers(body, subject, []string{"brute force", "brute-force"}) {
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	} else if cveMatch := regexp.MustCompile(`(CVE-\d{4}-\d{4,7})`).FindString(body); cveMatch != "" {
		event.EventTypes = []events.EventType{events.NewCVE(cveMatch, "", "")}
	} else if checkMarkers(body, subject, []string{"ddos", " dos"}) {
		event.EventTypes = []events.EventType{events.NewDDoS()}
	} else if checkMarkers(body, subject, []string{"malware", "cobalt strike"}) {
		malwareName := ""
		if strings.Contains(strings.ToLower(body), "cobalt strike") || strings.Contains(strings.ToLower(subject), "cobalt strike") {
			malwareName = "Cobalt Strike"
		}
		event.EventTypes = []events.EventType{events.NewMalware(malwareName)}
	} else if checkMarkers(body, subject, []string{"web application attack"}) {
		event.EventTypes = []events.EventType{events.NewWebHack()}
	} else if checkMarkers(body, subject, []string{"vulnerable elasticsearch"}) {
		event.EventTypes = []events.EventType{events.NewOpen("elasticsearch")}
	} else if checkMarkers(body, subject, []string{"android debug bridge"}) {
		event.EventTypes = []events.EventType{events.NewOpen("adb")}
	} else if checkMarkers(body, subject, []string{"scanning activities", "port scan"}) {
		event.EventTypes = []events.EventType{events.NewPortScan()}
	} else if checkMarkers(body, subject, []string{"phishing"}) {
		event.EventTypes = []events.EventType{events.NewPhishing()}
	} else if checkMarkers(body, subject, []string{"botnet"}) {
		event.EventTypes = []events.EventType{events.NewBot("")}
	} else if checkMarkers(body, subject, []string{"defacement"}) {
		event.EventTypes = []events.EventType{events.NewDefacement()}
	} else if checkMarkers(body, subject, []string{"malicious activities", "malicious urls", "malicious network", "possible attacks against tcp or udp", "command and control", "c2 network"}) {
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
	} else {
		return nil, common.NewNewTypeError(subject)
	}

	// Try to extract IP from subject first
	ip := common.ExtractOneIP(subject)
	if ip != "" {
		event.IP = ip
	}

	// Set event date
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
