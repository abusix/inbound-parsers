package akamai

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	urlPattern = regexp.MustCompile(`(?i)(?P<url>(http|hxxp)s?://.*?)(\s|$)`)
)

func NewParser() *Parser {
	return &Parser{}
}

// keyMap maps subject keywords to event types
var keyMap = []struct {
	keywords  []string
	eventType func() events.EventType
}{
	{[]string{"botnet"}, func() events.EventType { return events.NewBot("") }},
	{[]string{"phishing"}, func() events.EventType { return events.NewPhishing() }},
	{[]string{"malicious", "other hacking", "please suspend", "policy violation", "domain takedown"}, func() events.EventType { return events.NewMaliciousActivity() }},
	{[]string{"portscan", "port scan"}, func() events.EventType { return events.NewPortScan() }},
	{[]string{"loginattack", "logginattack", "brute force"}, func() events.EventType { return events.NewLoginAttack("", "") }},
	{[]string{"dmca", "content infringement", "rights infringement"}, func() events.EventType { return events.NewCopyright("", "", "") }},
	{[]string{"trademark"}, func() events.EventType { return events.NewTrademark("", nil, "", "") }},
	{[]string{"child", "sexual abuse"}, func() events.EventType { return events.NewChildAbuse() }},
	{[]string{"malware"}, func() events.EventType { return events.NewMalwareHosting() }},
	{[]string{"vulnerability"}, func() events.EventType { return events.NewOpen("") }},
	{[]string{"ddos"}, func() events.EventType { return events.NewDDoS() }},
}

func parseAbuseAkamai(subject, dateStr, body string) ([]*events.Event, error) {
	event := events.NewEvent("akamai")
	event.EventDate = email.ParseDate(dateStr)

	// Determine event type based on subject keywords
	for _, km := range keyMap {
		for _, keyword := range km.keywords {
			if strings.Contains(subject, keyword) {
				event.EventTypes = []events.EventType{km.eventType()}
				break
			}
		}
	}

	// Clean up HTML tags
	body = strings.ReplaceAll(body, "<p>", "\n")
	body = strings.ReplaceAll(body, "</p>", "\n")
	body = strings.ReplaceAll(body, "</h3>", "")

	// Split by <h3> tags to get sections
	sections := strings.Split(body, "<h3>")

	for _, section := range sections {
		if section == "" {
			continue
		}

		if strings.Contains(section, "Date Time Of Event") {
			if eventDate := common.GetNonEmptyLineAfter(section, "Date Time Of Event"); eventDate != "" {
				event.EventDate = email.ParseDate(eventDate)
			}
		}

		if strings.Contains(section, "Source Ip Address") {
			if ip := common.GetNonEmptyLineAfter(section, "Ip Address"); ip != "" {
				if strings.Contains(ip, "/") {
					ip = strings.Split(ip, "/")[0]
				}
				event.IP = ip
			}
		}

		if strings.Contains(section, "Source Url") || strings.Contains(section, "Infringing Url") {
			if url := strings.TrimSpace(common.GetNonEmptyLineAfter(section, "Url")); url != "" {
				event.URL = url
			}
		}

		if strings.Contains(section, "Evidence Logs") {
			if logs := strings.TrimSpace(common.GetNonEmptyLineAfter(section, "Evidence Logs")); logs != "" && logs != "N/A" {
				event.AddEventDetailSimple("evidence_logs", logs)
			}
		}

		if strings.Contains(section, "Email Address") {
			if emailAddr := common.GetNonEmptyLineAfter(section, "Email Address"); emailAddr != "" {
				event.AddEventDetail(&events.Organisation{
					Name:         "reporter",
					ContactEmail: emailAddr,
				})
			}
		}

		if strings.Contains(section, "Net-Storage Path") {
			if path := common.GetNonEmptyLineAfter(section, "Net-Storage Path"); path != "" {
				event.AddEventDetailSimple("net_storage_path", path)
			}
		}
	}

	return []*events.Event{event}, nil
}

func parseAkamai(subject, dateStr, body string) ([]*events.Event, error) {
	event := events.NewEvent("akamai")
	event.EventDate = email.ParseDate(dateStr)

	// Determine event type based on subject keywords
	if strings.Contains(subject, "botnet") {
		event.EventTypes = []events.EventType{events.NewBot("")}
	} else if strings.Contains(subject, "phishing") || strings.Contains(subject, "fake") {
		event.EventTypes = []events.EventType{events.NewPhishing()}
	} else if strings.Contains(subject, "malicious") {
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
	} else if strings.Contains(subject, "portscan") {
		event.EventTypes = []events.EventType{events.NewPortScan()}
	} else if strings.Contains(subject, "logginattack") {
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	} else if strings.Contains(subject, "network activity") ||
		strings.Contains(subject, "unusual activity") ||
		strings.Contains(subject, "infringement") ||
		strings.Contains(subject, "please suspend") ||
		strings.Contains(subject, "abuse report") {
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
	}

	// Try to extract IP from subject
	if ip := common.ExtractOneIP(subject); ip != "" {
		event.IP = ip
	}

	// If no IP found, try to extract from body
	if event.IP == "" {
		bodyLower := strings.ToLower(body)
		for _, tag := range []string{"(attacker's ip)=", "ip:"} {
			if ipCandidate := common.FindStringWithoutMarkers(bodyLower, tag, ""); ipCandidate != "" {
				ipCandidate = strings.ReplaceAll(ipCandidate, "[", "")
				ipCandidate = strings.ReplaceAll(ipCandidate, "]", "")
				ipCandidate = strings.ReplaceAll(ipCandidate, ")", "")
				event.IP = ipCandidate
				break
			}
		}
	}

	// Try to extract URL from body
	if match := urlPattern.FindStringSubmatch(body); len(match) > 0 {
		for i, name := range urlPattern.SubexpNames() {
			if name == "url" && i < len(match) {
				event.URL = match[i]
				break
			}
		}
	}

	// Only return event if we found IP or URL
	if event.IP != "" || event.URL != "" {
		return []*events.Event{event}, nil
	}

	return nil, common.NewParserError("no IP or URL found")
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	// Get date from headers
	var dateStr string
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		dateStr = dateHeader[0]
	}

	// Get from address
	var fromAddr string
	if fromHeader, ok := serializedEmail.Headers["from"]; ok && len(fromHeader) > 0 {
		fromAddr = fromHeader[0]
	}

	// Check if this is from abuse@akamai.com
	if strings.Contains(fromAddr, "abuse@akamai.com") {
		return parseAbuseAkamai(subjectLower, dateStr, body)
	}

	// Check if subject contains known keywords
	keywords := []string{
		"botnet",
		"phishing",
		"malicious",
		"infringement",
		"activity",
		"portscan",
		"please suspend",
		"logginattack",
		"abuse report",
		"fake",
	}

	for _, keyword := range keywords {
		if strings.Contains(subjectLower, keyword) {
			return parseAkamai(subjectLower, dateStr, body)
		}
	}

	return nil, common.NewNewTypeError(subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
