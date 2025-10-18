package buycheaprdp

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

// findStringWithoutMarkersToNewline finds text after a marker until newline
// This mimics Python's find_string_without_markers with default endswith=''
func findStringWithoutMarkersToNewline(text, marker string) string {
	// Determine line break style
	lineBreak := "\n"
	if strings.Contains(text, "\r\n") {
		lineBreak = "\r\n"
	}

	return common.FindStringWithoutMarkers(text, marker, lineBreak)
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)

	// Extract case ID using regex
	var caseID string
	caseIDPattern := regexp.MustCompile(`#(\S*\d+)`)
	if matches := caseIDPattern.FindStringSubmatch(bodyLower); len(matches) > 1 {
		caseID = matches[1]
	}

	// Extract status, priority, and subject
	status := strings.TrimSpace(findStringWithoutMarkersToNewline(bodyLower, "status:"))
	priority := strings.TrimSpace(findStringWithoutMarkersToNewline(bodyLower, "priority:"))
	subject := findStringWithoutMarkersToNewline(bodyLower, "subject:")

	// Determine event type based on subject
	var eventType events.EventType
	if strings.Contains(subject, "login-attack") {
		eventType = events.NewLoginAttack("", "")
	} else if strings.Contains(subject, "spamvertised") {
		eventType = events.NewSpamvertised()
	} else if strings.Contains(subject, "spam") && !strings.Contains(subject, "spamhaus") {
		eventType = events.NewSpam()
	} else if strings.Contains(subject, "port-scan") {
		eventType = events.NewPortScan()
	} else if strings.Contains(subject, "dns-blocklist") {
		eventType = events.NewDNSBlocklist()
	} else if strings.Contains(subject, "malware") {
		eventType = events.NewMalware("")
	} else if strings.Contains(subject, "exploit") {
		eventType = events.NewExploit()
	} else if strings.Contains(subject, "ddos") {
		eventType = events.NewDDoS()
	} else if strings.Contains(subject, "hacking attempt") {
		eventType = events.NewWebHack()
	} else if strings.Contains(subject, "spamhaus sbl") {
		eventType = events.NewBlacklist()
	} else if strings.Contains(subject, "suspicious activity") || strings.Contains(subject, "fraud") {
		eventType = events.NewFraud()
	} else {
		return nil, common.NewNewTypeError(subject)
	}

	// Create event
	event := events.NewEvent("buycheaprdp")
	event.EventTypes = []events.EventType{eventType}
	event.IP = subject // Per Python code, IP is set to subject

	// Set event date from email header
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		event.EventDate = email.ParseDate(dateHeader[0])
	}

	// Add external case information
	event.AddEventDetail(&events.ExternalCaseInformation{
		CaseID:   caseID,
		Status:   status,
		Severity: priority,
	})

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
