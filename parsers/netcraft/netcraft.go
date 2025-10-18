package netcraft

import (
	"fmt"
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

// getTextLinebreak determines the linebreak style used in the text
func getTextLinebreak(text string) string {
	if strings.Contains(text, "\r\n") {
		return "\r\n"
	}
	return "\n"
}

// parsePhishing parses phishing reports
func parsePhishing(serializedEmail *email.SerializedEmail, subject, externalID string) ([]*events.Event, error) {
	var evts []*events.Event

	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	body = common.RemoveCarriageReturn(body)
	if body == "" {
		return nil, fmt.Errorf("empty body")
	}

	var marker string
	if strings.Contains(body, "\nhxxp") {
		marker = "\nhxxp"
	} else {
		marker = "\nhttp"
	}

	startIndex := strings.Index(body, marker)
	var urls []string

	if startIndex != -1 {
		endIndex := strings.Index(body[startIndex:], "\n\n")
		var urlsText string
		if endIndex != -1 {
			urlsText = body[startIndex : startIndex+endIndex]
		} else {
			urlsText = body[startIndex:]
		}
		urls = strings.Split(strings.TrimSpace(urlsText), "\n")
	}

	if len(urls) == 0 {
		// Try to find URLs in subject
		re := regexp.MustCompile(`hxxp.*`)
		urls = re.FindAllString(subject, -1)
	}

	for _, line := range urls {
		url := common.CleanURL(line)
		if strings.HasPrefix(url, "http") {
			event := events.NewEvent("netcraft")
			if dateStr, ok := serializedEmail.Headers["date"]; ok && len(dateStr) > 0 {
				event.EventDate = email.ParseDate(dateStr[0])
			}
			event.EventTypes = []events.EventType{events.NewPhishing()}
			url = strings.Split(url, "[")[0]
			event.URL = url
			event.IP = common.ExtractOneIP(url)
			event.AddEventDetail(&events.ExternalID{ID: externalID})
			evts = append(evts, event)
		}
	}

	return evts, nil
}

// parseScamSite parses scam site reports
func parseScamSite(serializedEmail *email.SerializedEmail, body, externalID string) ([]*events.Event, error) {
	var evts []*events.Event

	blockAround := common.GetBlockAround(body, "on your network:")
	ip := ""
	if len(blockAround) > 0 {
		ip = common.ExtractOneIP(strings.Join(blockAround, " "))
	}

	data := blockAround
	if len(data) > 1 {
		data = data[1:]
	} else {
		data = common.GetBlockAfterWithStop(body, "on your network:", "")
	}

	for _, entry := range data {
		event := events.NewEvent("netcraft")
		if dateStr, ok := serializedEmail.Headers["date"]; ok && len(dateStr) > 0 {
			event.EventDate = email.ParseDate(dateStr[0])
		}
		event.EventTypes = []events.EventType{events.NewFraud()}
		event.IP = ip
		url := common.CleanURL(entry)
		event.URL = strings.Split(url, "[")[0]
		event.AddEventDetail(&events.ExternalID{ID: externalID})
		evts = append(evts, event)
	}

	return evts, nil
}

// parseFraud parses fraud reports
func parseFraud(serializedEmail *email.SerializedEmail, subject, externalID string) ([]*events.Event, error) {
	url := ""

	// Try multiple regex patterns
	urlRe := regexp.MustCompile(`hxxp.*`)
	if match := urlRe.FindString(subject); match != "" {
		url = common.CleanURL(match)
	} else {
		fraudRe := regexp.MustCompile(`(?i)fraudulent domain name at (.*)`)
		if match := fraudRe.FindStringSubmatch(subject); match != nil && len(match) > 1 {
			url = common.CleanURL(match[1])
		}
	}

	event := events.NewEvent("netcraft")
	if dateStr, ok := serializedEmail.Headers["date"]; ok && len(dateStr) > 0 {
		event.EventDate = email.ParseDate(dateStr[0])
	}
	event.IP = common.ExtractOneIP(subject)
	event.URL = url
	event.EventTypes = []events.EventType{events.NewFraud()}
	event.AddEventDetail(&events.ExternalID{ID: externalID})

	return []*events.Event{event}, nil
}

// parseMalware parses malware reports
func parseMalware(serializedEmail *email.SerializedEmail, body, subject, externalID string) ([]*events.Event, error) {
	var evts []*events.Event
	addedURLs := make(map[string]bool)

	urlRe := regexp.MustCompile(`hxxp.*`)
	urls := urlRe.FindAllString(body, -1)
	if len(urls) == 0 {
		urls = urlRe.FindAllString(subject, -1)
	}

	for _, url := range urls {
		urlStr := strings.TrimSpace(strings.Split(url, " ")[0])
		urlStr = common.CleanURL(urlStr)
		if !addedURLs[urlStr] {
			addedURLs[urlStr] = true
			event := events.NewEvent("netcraft")
			if dateStr, ok := serializedEmail.Headers["date"]; ok && len(dateStr) > 0 {
				event.EventDate = email.ParseDate(dateStr[0])
			}
			// Try to extract IP from url or urlStr
			if ip := common.ExtractOneIP(url); ip != "" {
				event.IP = ip
			} else if ip := common.ExtractOneIP(urlStr); ip != "" {
				event.IP = ip
			}
			event.URL = urlStr
			event.EventTypes = []events.EventType{events.NewMalware("")}
			event.AddEventDetail(&events.ExternalID{ID: externalID})
			evts = append(evts, event)
		}
	}

	if len(evts) == 0 {
		event := events.NewEvent("netcraft")
		event.EventTypes = []events.EventType{events.NewMalware("")}
		if dateStr, ok := serializedEmail.Headers["date"]; ok && len(dateStr) > 0 {
			event.EventDate = email.ParseDate(dateStr[0])
		}
		subj, _ := common.GetSubject(serializedEmail, false)
		event.IP = subj
		evts = append(evts, event)
	}

	return evts, nil
}

// parseLoginAttack parses login attack reports
func parseLoginAttack(serializedEmail *email.SerializedEmail, subject, externalID, date string) ([]*events.Event, error) {
	event := events.NewEvent("netcraft")
	event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

	event.IP = subject

	// If subject is not an IP, try to find it in body
	if common.IsIP(subject) == "" {
		body, err := common.GetBody(serializedEmail, false)
		if err == nil {
			bodyLower := strings.ToLower(body)
			for _, tag := range []string{"ip address:", "ip adreso:"} {
				if strings.Contains(bodyLower, tag) {
					ip := common.GetNonEmptyLineAfter(bodyLower, tag)
					if ip != "" {
						event.IP = ip
						break
					}
				}
			}
		}
		if event.IP == "" && common.IsIP(subject) == "" {
			return nil, fmt.Errorf("couldn't get IP")
		}
	}

	event.AddEventDetail(&events.ExternalID{ID: externalID})

	// Try to parse the date
	if date != "" {
		if parsedDate := email.ParseDate(date); parsedDate != nil {
			event.EventDate = parsedDate
		}
	}
	if event.EventDate == nil {
		if dateStr, ok := serializedEmail.Headers["date"]; ok && len(dateStr) > 0 {
			event.EventDate = email.ParseDate(dateStr[0])
		}
	}

	return []*events.Event{event}, nil
}

// parseWebHack parses web hack reports
func parseWebHack(subject, externalID string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	event := events.NewEvent("netcraft")
	event.EventTypes = []events.EventType{events.NewWebHack()}
	event.IP = subject
	event.AddEventDetail(&events.ExternalID{ID: externalID})
	if dateStr, ok := serializedEmail.Headers["date"]; ok && len(dateStr) > 0 {
		event.EventDate = email.ParseDate(dateStr[0])
	}

	return []*events.Event{event}, nil
}

// parseCompromiseWebsite parses compromised website reports
func parseCompromiseWebsite(externalID string, serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	line := common.GetNonEmptyLineAfter(body, "without user consent:")
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil, fmt.Errorf("no identifying information found")
	}

	url := parts[0]
	ip := parts[1]

	event := events.NewEvent("netcraft")
	event.EventTypes = []events.EventType{events.NewWebHack()}
	event.IP = ip
	event.URL = common.CleanURL(url)
	event.AddEventDetail(&events.ExternalID{ID: externalID})
	if dateStr, ok := serializedEmail.Headers["date"]; ok && len(dateStr) > 0 {
		event.EventDate = email.ParseDate(dateStr[0])
	}

	return []*events.Event{event}, nil
}

// parseSpam parses spam reports
func parseSpam(externalID string, serializedEmail *email.SerializedEmail, subject string) ([]*events.Event, error) {
	event := events.NewEvent("netcraft")
	event.EventTypes = []events.EventType{events.NewSpam()}
	if dateStr, ok := serializedEmail.Headers["date"]; ok && len(dateStr) > 0 {
		event.EventDate = email.ParseDate(dateStr[0])
	}
	event.AddEventDetail(&events.ExternalID{ID: externalID})

	urlRe := regexp.MustCompile(`(hxxp\S*)`)
	if match := urlRe.FindStringSubmatch(subject); match != nil {
		event.URL = common.CleanURL(match[1])
	} else {
		return nil, fmt.Errorf("format changed adapt the parser")
	}

	return []*events.Event{event}, nil
}

// parseUnauthorisedMobileApp parses unauthorized mobile app reports
func parseUnauthorisedMobileApp(externalID string, serializedEmail *email.SerializedEmail, subject string) ([]*events.Event, error) {
	event := events.NewEvent("netcraft")
	event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}
	if dateStr, ok := serializedEmail.Headers["date"]; ok && len(dateStr) > 0 {
		event.EventDate = email.ParseDate(dateStr[0])
	}
	event.AddEventDetail(&events.ExternalID{ID: externalID})

	urlRe := regexp.MustCompile(`(hxxp\S*)`)
	if match := urlRe.FindStringSubmatch(subject); match != nil {
		event.URL = common.CleanURL(match[1])
	} else {
		return nil, fmt.Errorf("format changed adapt the parser")
	}

	return []*events.Event{event}, nil
}

// parseVulnerableWebsite parses vulnerable website reports
func parseVulnerableWebsite(externalID string, serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	event := events.NewEvent("netcraft")
	if dateStr, ok := serializedEmail.Headers["date"]; ok && len(dateStr) > 0 {
		event.EventDate = email.ParseDate(dateStr[0])
	}
	event.AddEventDetail(&events.ExternalID{ID: externalID})

	cveNumber := common.FindStringWithoutMarkers(body, "(CVE-", ")")
	event.EventTypes = []events.EventType{events.NewCVE(fmt.Sprintf("CVE-%s", cveNumber), "", "")}

	linebreak := getTextLinebreak(body)
	host := common.FindString(body, "hxxp", linebreak)
	parts := strings.SplitN(host, " ", 2)
	if len(parts) >= 2 {
		event.URL = parts[0]
		event.IP = parts[1]
	} else if len(parts) == 1 {
		event.URL = parts[0]
	}

	return []*events.Event{event}, nil
}

// parseVulnerableServer parses vulnerable server reports
func parseVulnerableServer(externalID string, serializedEmail *email.SerializedEmail, bodyLower, subject string) ([]*events.Event, error) {
	event := events.NewEvent("netcraft")
	if dateStr, ok := serializedEmail.Headers["date"]; ok && len(dateStr) > 0 {
		event.EventDate = email.ParseDate(dateStr[0])
	}
	event.AddEventDetail(&events.ExternalID{ID: externalID})

	serviceString := common.FindStringWithoutMarkers(bodyLower, "unrestricted inbound access to ", ".")
	event.EventTypes = []events.EventType{events.NewOpen(common.MapServiceStrings(serviceString))}
	event.IP = subject

	return []*events.Event{event}, nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)
	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	subject = strings.TrimSpace(subject)
	subjectLower := strings.ToLower(subject)

	externalID := strings.TrimSpace(common.FindStringWithoutMarkers(subject, "Issue", ":"))
	date := common.FindStringWithoutMarkers(body, "We last observed", "")

	var events []*events.Event

	if strings.Contains(subjectLower, "phishing") {
		events, err = parsePhishing(serializedEmail, subject, externalID)
	} else if strings.Contains(body, "on your network:") {
		events, err = parseScamSite(serializedEmail, body, externalID)
	} else if strings.Contains(subjectLower, "fraud") || strings.Contains(subjectLower, "fake") {
		events, err = parseFraud(serializedEmail, subject, externalID)
	} else if strings.Contains(subjectLower, "malware") {
		events, err = parseMalware(serializedEmail, body, subject, externalID)
	} else if strings.Contains(subjectLower, "brute force") {
		events, err = parseLoginAttack(serializedEmail, subject, externalID, date)
	} else if strings.Contains(subjectLower, "address attacking a web application") {
		events, err = parseWebHack(subject, externalID, serializedEmail)
	} else if strings.Contains(bodyLower, "compromise of a website") {
		events, err = parseCompromiseWebsite(externalID, serializedEmail, body)
	} else if strings.Contains(subjectLower, "spam") {
		events, err = parseSpam(externalID, serializedEmail, subject)
	} else if strings.Contains(subjectLower, "unauthorised mobile app") {
		events, err = parseUnauthorisedMobileApp(externalID, serializedEmail, subject)
	} else if strings.Contains(subjectLower, "vulnerable web application") {
		events, err = parseVulnerableWebsite(externalID, serializedEmail, body)
	} else if strings.Contains(subjectLower, "potentially vulnerable server") {
		events, err = parseVulnerableServer(externalID, serializedEmail, bodyLower, subject)
	} else {
		return nil, &common.NewTypeError{Subject: subject}
	}

	if err != nil {
		return nil, err
	}

	if len(events) == 0 {
		return nil, &common.ParserError{Message: "no event created"}
	}

	return events, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
