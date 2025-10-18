package ipxo

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	ipPattern2         = regexp.MustCompile(`(\[?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\]?)`)
	legitimateURLPattern = regexp.MustCompile(`(?i)(Legitimate Brand URL\'s:)[^h.]*(\S+)`)
	evidenceURLPattern   = regexp.MustCompile(`(?i)(Screenshot of infringing content:)[^h.]*(\S+)`)
)

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	bodyLower := strings.ToLower(body)

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	// Get event date
	dateFallback := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateFallback = dateHeaders[0]
	}
	eventDate := email.ParseDate(dateFallback)

	// Dispatch to appropriate parser based on subject/body content
	if strings.Contains(subjectLower, "abuse originating") {
		return parseSimple(subjectLower, eventDate), nil
	}

	if strings.Contains(subjectLower, "phishing") {
		return parsePhishing(bodyLower, eventDate)
	}

	if strings.Contains(subjectLower, "hacking") || strings.Contains(bodyLower, "email was hacked") {
		return parseHacking(bodyLower, eventDate)
	}

	if strings.Contains(subjectLower, "ddos") {
		return parseDDoS(bodyLower, eventDate)
	}

	if strings.Contains(subjectLower, "copyright") {
		return parseCopyright(bodyLower, eventDate)
	}

	if strings.Contains(subjectLower, "spam") {
		return parseSimpleFormats(bodyLower, eventDate, "spam")
	}

	if strings.Contains(subjectLower, "brute force attack") || strings.Contains(bodyLower, "brute force attack") {
		return parseBruteForce(bodyLower, eventDate)
	}

	if strings.Contains(subjectLower, "port scanning") {
		return parseSimpleFormats(bodyLower, eventDate, "portscanning")
	}

	if strings.Contains(bodyLower, "sexual abuse of children investigation") || strings.Contains(bodyLower, "child pornography") {
		return parseSimpleFormats(bodyLower, eventDate, "childabuse")
	}

	if strings.Contains(subjectLower, "violence") {
		return parseViolence(bodyLower, eventDate)
	}

	return []*events.Event{}, nil
}

// parseSimple handles the simple "abuse originating" format
func parseSimple(subject string, eventDate *time.Time) []*events.Event {
	event := events.NewEvent("ipxo")
	event.EventDate = eventDate

	event.IP = subject
	eventType := common.FindStringWithoutMarkers(subject, "[", "]")
	event.EventTypes = []events.EventType{getEventWithType(eventType, "", "", "")}

	return []*events.Event{event}
}

// parsePhishing handles phishing reports
func parsePhishing(body string, eventDate *time.Time) ([]*events.Event, error) {
	eventTemplate := events.NewEvent("ipxo")
	eventTemplate.EventDate = eventDate

	officialURL := getLegitimateURL(body)

	// Add evidence URL if present
	if match := evidenceURLPattern.FindStringSubmatch(body); len(match) > 2 {
		evidence := &events.Evidence{
			URLs: []events.UrlStore{
				{Description: "evidence", URL: match[2]},
			},
		}
		eventTemplate.AddEventDetail(evidence)
	}

	eventTemplate.AddEventDetail(getOrganisation(body, ""))

	// Get IPs
	allIPs := getIPs(body)

	// Get URLs
	allURLs := getURLs(body, []string{
		"phishing content:",
		"url of the abusive site for takedown:",
		"phishing attack(s) hosted on:",
		"the url(s) of the phishing site:",
	}, "")

	return createEvent(eventTemplate, "phishing", allIPs, allURLs, officialURL, "")
}

// parseCopyright handles copyright infringement reports
func parseCopyright(body string, eventDate *time.Time) ([]*events.Event, error) {
	eventTemplate := events.NewEvent("ipxo")
	eventTemplate.EventDate = eventDate

	eventTemplate.AddEventDetail(getOrganisation(body, "\n"))

	officialURL := getLegitimateURL(body)
	allIPs := getIPs(body)
	allURLs := getURLs(body, []string{
		"through the following urls",
		"url that is currently redirecting to",
	}, ". ")

	copyrightOwner := ""
	for _, ownerTag := range []string{"on behalf of", "brand abused:"} {
		if strings.Contains(body, ownerTag) {
			if ownerTag == "on behalf of" {
				copyrightOwner = strings.TrimSpace(common.FindStringWithoutMarkers(body, ownerTag, ". "))
			} else {
				copyrightOwner = strings.TrimSpace(common.FindStringWithoutMarkers(body, ownerTag, ""))
			}
			break
		}
	}

	return createEvent(eventTemplate, "copyright", allIPs, allURLs, officialURL, copyrightOwner)
}

// parseDDoS handles DDoS attack reports
func parseDDoS(body string, eventDate *time.Time) ([]*events.Event, error) {
	eventTemplate := events.NewEvent("ipxo")
	eventTemplate.EventDate = eventDate

	eventTemplate.AddEventDetail(getOrganisation(body, ""))

	allIPs := getIPs(body)
	if len(allIPs) == 0 {
		tag := "ddos attack that took place"
		if strings.Contains(body, tag) {
			ipsBlock := common.GetBlockAfterWithStop(body, tag+"\n\n", "")
			for _, ip := range ipsBlock {
				if cleanIP := common.IsIP(ip); cleanIP != "" {
					allIPs = append(allIPs, cleanIP)
				}
			}
		}
	}

	return createEvent(eventTemplate, "ddos", allIPs, nil, "", "")
}

// parseHacking handles hacking/web hack reports
func parseHacking(body string, eventDate *time.Time) ([]*events.Event, error) {
	eventTemplate := events.NewEvent("ipxo")
	eventTemplate.EventDate = eventDate

	eventTemplate.AddEventDetail(getOrganisation(body, ""))

	allIPs := getIPs(body)

	for _, tag := range []string{
		"other addresses used by the same person:",
		"other ips included in this event are:",
	} {
		if strings.Contains(body, tag) {
			ipsBlock := common.GetBlockAfterWithStop(body, tag+"\n\n", "")
			for _, line := range ipsBlock {
				for _, ip := range strings.Split(strings.ReplaceAll(strings.ReplaceAll(line, ", ", "-"), ". ", "-"), "-") {
					if cleanIP := common.IsIP(ip); cleanIP != "" {
						allIPs = append(allIPs, cleanIP)
					}
				}
			}
		}
	}

	return createEvent(eventTemplate, "webHack", allIPs, nil, "", "")
}

// parseBruteForce handles brute force attack reports
func parseBruteForce(body string, eventDate *time.Time) ([]*events.Event, error) {
	eventTemplate := events.NewEvent("ipxo")
	eventTemplate.EventDate = eventDate

	eventTemplate.AddEventDetail(getOrganisation(body, "\n"))

	allIPs := getIPs(body)
	if strings.Contains(body, "brute force attacks by") {
		ipsString := common.FindStringWithoutMarkers(body, "brute force attacks by", "against")
		for _, ip := range strings.Split(strings.ReplaceAll(ipsString, "and", ","), ",") {
			cleanIP := strings.TrimSpace(ip)
			if common.IsIP(cleanIP) != "" {
				found := false
				for _, existingIP := range allIPs {
					if existingIP == cleanIP {
						found = true
						break
					}
				}
				if !found {
					allIPs = append(allIPs, cleanIP)
				}
			}
		}
	}

	if len(allIPs) == 0 {
		if ip := common.FindStringWithoutMarkers(body, "user that is using one of your ips (", ")"); ip != "" {
			allIPs = append(allIPs, ip)
		}
	}

	return createEvent(eventTemplate, "bruteforce", allIPs, nil, "", "")
}

// parseSimpleFormats handles simple event formats (spam, port scanning, child abuse)
func parseSimpleFormats(body string, eventDate *time.Time, eventType string) ([]*events.Event, error) {
	eventTemplate := events.NewEvent("ipxo")
	eventTemplate.EventDate = eventDate

	eventTemplate.AddEventDetail(getOrganisation(body, "\n"))

	allIPs := getIPs(body)

	return createEvent(eventTemplate, eventType, allIPs, nil, "", "")
}

// parseViolence handles violence reports
func parseViolence(body string, eventDate *time.Time) ([]*events.Event, error) {
	eventTemplate := events.NewEvent("ipxo")
	eventTemplate.EventDate = eventDate

	eventTemplate.AddEventDetail(getOrganisation(body, "\n"))

	startIndex := strings.Index(body, "ip logs reference the account in question")
	endIndex := strings.Index(body, "please respond as soon")

	var allIPs []string
	if startIndex != -1 && endIndex != -1 {
		newBody := body[startIndex:endIndex]
		matches := ipPattern2.FindAllString(newBody, -1)
		for _, match := range matches {
			if cleanIP := common.IsIP(match); cleanIP != "" {
				allIPs = append(allIPs, cleanIP)
			}
		}
	}

	return createEvent(eventTemplate, "violence", allIPs, nil, "", "")
}

// Helper functions

func getIPs(body string) []string {
	var allIPs []string

	// Method 1: Extract from "new report abuse complaint -"
	if ipsString := common.FindStringWithoutMarkers(body, "new report abuse complaint -", "-"); ipsString != "" {
		ipsString = strings.ReplaceAll(ipsString, ";", ",")
		ipsString = strings.ReplaceAll(ipsString, "/", ",")
		ipsString = strings.ReplaceAll(ipsString, " ", ",")
		for _, ip := range strings.Split(ipsString, ",") {
			ip = strings.TrimSpace(strings.Split(ip, "(")[0])
			if cleanIP := common.IsIP(ip); cleanIP != "" {
				allIPs = append(allIPs, cleanIP)
			}
		}
	}

	// Method 2: Look for specific tags
	if len(allIPs) == 0 {
		for _, tag := range []string{"ip address:", "their ip is"} {
			if ip := common.GetNonEmptyLineAfter(strings.ReplaceAll(body, tag, tag+"\n\n"), tag); ip != "" {
				if cleanIP := common.IsIP(strings.TrimSpace(ip)); cleanIP != "" {
					allIPs = append(allIPs, cleanIP)
					break
				}
			}
		}
	}

	// Method 3: Extract from "using the ip address"
	if len(allIPs) == 0 {
		if ip := common.FindStringWithoutMarkers(body, "using the ip address", ". "); ip != "" {
			if cleanIP := common.IsIP(strings.TrimSpace(ip)); cleanIP != "" {
				allIPs = append(allIPs, cleanIP)
			}
		}
	}

	return allIPs
}

func getOrganisation(body, endswith string) *events.Organisation {
	return &events.Organisation{
		Name:         "reporter",
		ContactName:  strings.TrimSpace(common.FindStringWithoutMarkers(body, "company name:", endswith)),
		ContactPhone: strings.TrimSpace(common.FindStringWithoutMarkers(body, "phone:", endswith)),
	}
}

func getURLs(body string, phsURLTags []string, endswith string) []string {
	var allURLs []string

	if len(phsURLTags) == 0 {
		return allURLs
	}

	phsURLTag := phsURLTags[0]
	if strings.Contains(body, phsURLTag) {
		phishingURLBlock := common.GetBlockAfterWithStop(strings.ReplaceAll(body, phsURLTag, phsURLTag+"\n"), phsURLTag, "")
		for _, url := range phishingURLBlock {
			allURLs = append(allURLs, common.CleanURL(url))
		}
	}

	if len(allURLs) == 0 {
		for _, tag := range phsURLTags[1:] {
			if strings.Contains(body, tag) {
				url := common.CleanURL(common.FindStringWithoutMarkers(body, tag, endswith))
				allURLs = append(allURLs, url)
				break
			}
		}
	}

	return allURLs
}

func getLegitimateURL(body string) string {
	if match := legitimateURLPattern.FindStringSubmatch(body); len(match) > 2 {
		return match[2]
	}

	if strings.Contains(body, "official website at") {
		return common.FindStringWithoutMarkers(body, "official website at", "")
	}

	if strings.Contains(body, "original website:") {
		return common.FindStringWithoutMarkers(body, "original website:", "")
	}

	return ""
}

func getEventWithType(eventType, url, officialURL, copyrightOwner string) events.EventType {
	switch eventType {
	case "phishing":
		if officialURL != "" {
			return events.NewPhishingWithOfficialURL(officialURL)
		}
		return events.NewPhishing()
	case "copyright":
		return events.NewCopyright(url, copyrightOwner, "")
	case "webHack":
		return events.NewWebHack()
	case "ddos":
		return events.NewDDoS()
	case "bruteforce", "login-attack":
		return events.NewLoginAttack("", "")
	case "portscanning", "port-scan":
		return events.NewPortScan()
	case "childabuse":
		return events.NewChildAbuse()
	case "violence":
		return events.NewViolence()
	case "spam":
		return events.NewSpam()
	case "trademark":
		return events.NewTrademark("", nil, "", "")
	case "malware":
		return events.NewMalware("")
	case "spamvertised":
		return events.NewSpamvertised()
	default:
		return events.NewUnknown()
	}
}

func createEvent(eventTemplate *events.Event, eventType string, allIPs, allURLs []string, officialURL, copyrightOwner string) ([]*events.Event, error) {
	// Zero/one URL + many IPs: One event per IP, all of them have the same URL (or no URL)
	if len(allIPs) >= 1 && len(allURLs) <= 1 {
		url := ""
		if len(allURLs) == 1 {
			url = allURLs[0]
		}
		return createEventAuxiliar(allIPs, eventTemplate, eventType, officialURL, copyrightOwner, "", url, false, true), nil
	}

	// Zero/one IP + many URLs: One event per URL, all of them have the same IP (or no IP)
	if len(allURLs) >= 1 && len(allIPs) <= 1 {
		ip := ""
		if len(allIPs) == 1 {
			ip = allIPs[0]
		}
		return createEventAuxiliar(allURLs, eventTemplate, eventType, officialURL, copyrightOwner, ip, "", true, false), nil
	}

	// Many IPs and many URLs: One event per IP and one event per URL, no shared information
	if len(allURLs) > 1 && len(allIPs) > 1 {
		ipEvents := createEventAuxiliar(allIPs, eventTemplate, eventType, officialURL, copyrightOwner, "", "", false, true)
		urlEvents := createEventAuxiliar(allURLs, eventTemplate, eventType, officialURL, copyrightOwner, "", "", true, false)
		return append(ipEvents, urlEvents...), nil
	}

	return nil, common.NewParserError("no ip or url found")
}

func createEventAuxiliar(list []string, eventTemplate *events.Event, eventType, officialURL, copyrightOwner, ip, url string, sharedIP, sharedURL bool) []*events.Event {
	var result []*events.Event

	for _, el := range list {
		// Deep copy event template
		event := events.NewEvent(eventTemplate.Parser)
		event.EventDate = eventTemplate.EventDate

		// Copy event details
		for _, detail := range eventTemplate.EventDetails {
			event.AddEventDetail(detail)
		}

		if !sharedIP {
			ip = el
		}
		event.IP = ip

		if !sharedURL {
			url = el
		}
		event.URL = url

		event.EventTypes = []events.EventType{getEventWithType(eventType, url, officialURL, copyrightOwner)}
		result = append(result, event)
	}

	return result
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
