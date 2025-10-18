// Package easysol implements the easysol.net parser
package easysol

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the easysol.net parser
type Parser struct{}

var ipPattern = regexp.MustCompile(`(?i)(IP Add?ress:)[^.0-9]*(\[?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\]?)`)

// Parse parses emails from easysol.net
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	if strings.Contains(subjectLower, "dmca notice") || strings.Contains(subjectLower, "dmca claim") {
		event, err := parseDMCA(serializedEmail, body)
		if err != nil {
			return nil, err
		}
		return []*events.Event{event}, nil
	} else if strings.Contains(subjectLower, "phishing site") || strings.Contains(subjectLower, "your website") {
		return parsePhishing(serializedEmail, body)
	} else if strings.Contains(subjectLower, "use of trademark") || strings.Contains(subjectLower, "trademark infringement") {
		return parseTrademark(serializedEmail, body)
	} else if strings.Contains(subjectLower, "spoofing") {
		return parseSpoofing(serializedEmail, body)
	} else if strings.Contains(subjectLower, "copyright") {
		return parseCopyright(serializedEmail, body)
	}

	return nil, common.NewNewTypeError(subject)
}

func parseDMCA(serializedEmail *email.SerializedEmail, body string) (*events.Event, error) {
	event := events.NewEvent("easysol")

	dateStr := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateStr = dateHeaders[0]
	}
	event.EventDate = email.ParseDate(dateStr)

	owner := common.FindStringWithoutMarkers(body, "of our client ", " (the \"Copyright's Owner\").")

	legitimateURL := ""
	legitimateRe := regexp.MustCompile(`(?i)(Legitimate (service )*site:)\s*(?P<url>.*)`)
	if match := legitimateRe.FindStringSubmatch(body); match != nil {
		legitimateURL = match[len(match)-1]
	}

	event.EventTypes = []events.EventType{events.NewCopyright("", owner, "")}
	if legitimateURL != "" {
		copyright := event.EventTypes[0].(*events.Copyright)
		copyright.OfficialURL = legitimateURL
	}

	infringingRe := regexp.MustCompile(`(?i)(following URL\(s\)[:|.])\s*(?P<url>.*)`)
	if match := infringingRe.FindStringSubmatch(body); match != nil {
		event.URL = match[len(match)-1]
	}

	if ip := common.FindStringWithoutMarkers(body, "IP Address: ", "\n"); ip != "" {
		event.IP = ip
	}

	return event, nil
}

func parsePhishing(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	urls := make(map[string]bool)

	tags := []string{"following URL(s):", "Infringing content:", "Phishing/Fraud attack:"}
	for _, tag := range tags {
		if strings.Contains(body, tag) {
			lines := strings.Split(body[strings.Index(body, tag):], "\n")
			for _, line := range lines[1:] {
				line = strings.TrimSpace(line)
				if line == "" {
					break
				}
				if strings.HasPrefix(line, "http") {
					urls[line] = true
				}
			}
			break
		}
	}

	var ip string
	if match := ipPattern.FindStringSubmatch(body); match != nil {
		ip = match[2]
	}

	legitimate := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Legitimate website:", "\n"))
	if legitimate == "" {
		legitimate = strings.TrimSpace(common.FindStringWithoutMarkers(body, "official website:", "\n"))
	}

	dateStr := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateStr = dateHeaders[0]
	}
	eventDate := email.ParseDate(dateStr)

	var eventsSlice []*events.Event
	for url := range urls {
		if !strings.Contains(url, "IP Address:") {
			url = strings.ReplaceAll(url, " ", "")
			event := events.NewEvent("easysol")
			if legitimate != "" {
				event.EventTypes = []events.EventType{events.NewPhishingWithOfficialURL(legitimate)}
			} else {
				event.EventTypes = []events.EventType{events.NewPhishing()}
			}
			if ip != "" {
				event.IP = ip
			}
			event.EventDate = eventDate
			event.URL = url
			eventsSlice = append(eventsSlice, event)
		}
	}

	return eventsSlice, nil
}

func parseTrademark(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	ipStr := common.FindStringWithoutMarkers(body, "IP: ", "\n")
	holder := strings.TrimSpace(strings.Trim(common.FindStringWithoutMarkers(body, "on behalf of our client", "\n"), "."))

	urls := make(map[string]bool)

	if strings.Contains(body, "Infringement website:") {
		url := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Infringement website:", "\n"))
		urls[url] = true
	} else if strings.Contains(body, "Infringing site:") {
		url := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Infringing site:", "\n"))
		urls[url] = true
	} else if strings.Contains(body, "following URL(s):") {
		lines := strings.Split(body[strings.Index(body, "following URL(s):"):], "\n")
		for _, line := range lines[1:] {
			line = strings.TrimSpace(line)
			if line == "" {
				break
			}
			parts := strings.Split(line, "<")
			urls[parts[0]] = true
		}
	}

	dateStr := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateStr = dateHeaders[0]
	}
	eventDate := email.ParseDate(dateStr)

	if len(urls) == 0 {
		return nil, common.NewParserError("infringing url not found")
	}
	if holder == "" {
		return nil, common.NewParserError("trademark holder not found")
	}

	var eventsSlice []*events.Event
	for url := range urls {
		event := events.NewEvent("easysol")
		event.EventTypes = []events.EventType{events.NewTrademark("", nil, holder, "")}
		event.EventDate = eventDate
		event.IP = ipStr
		event.URL = url
		eventsSlice = append(eventsSlice, event)
	}

	return eventsSlice, nil
}

func parseSpoofing(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	if match := ipPattern.FindStringSubmatch(body); match != nil {
		event := events.NewEvent("easysol")
		event.IP = match[2]
		dateStr := ""
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			dateStr = dateHeaders[0]
		}
		event.EventDate = email.ParseDate(dateStr)
		event.EventTypes = []events.EventType{events.NewIPSpoof("", "", false, "")}
		return []*events.Event{event}, nil
	}
	return nil, nil
}

func parseCopyright(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	bodyLower := strings.ToLower(body)
	legitimateURL := common.FindStringWithoutMarkers(bodyLower, "legitimate service site:", "\n")
	ip := common.FindStringWithoutMarkers(bodyLower, "ip address:", "\n")
	owner := common.FindStringWithoutMarkers(body, "on behalf of our client", "\n")

	dateStr := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateStr = dateHeaders[0]
	}
	eventDate := email.ParseDate(dateStr)

	var eventsSlice []*events.Event
	if strings.Contains(bodyLower, "following urls:") {
		lines := strings.Split(bodyLower[strings.Index(bodyLower, "following urls:"):], "\n")
		for _, line := range lines[1:] {
			line = strings.TrimSpace(line)
			if line == "" {
				break
			}
			event := events.NewEvent("easysol")
			event.EventDate = eventDate
			if ip != "" {
				event.IP = ip
			}
			copyright := events.NewCopyright("", owner, "")
			if legitimateURL != "" {
				copyright.OfficialURL = legitimateURL
			}
			event.EventTypes = []events.EventType{copyright}
			event.URL = line
			eventsSlice = append(eventsSlice, event)
		}
	}

	return eventsSlice, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
