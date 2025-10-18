// Package riskiq implements the RiskIQ parser
package riskiq

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the RiskIQ parser
type Parser struct{}

var (
	ownerRegex     = regexp.MustCompile(` *(.*) is the owner of the`)
	trademarkRegex = regexp.MustCompile(`.*"(.*)".*`)
	urlGobbler     = regexp.MustCompile(`(?P<url>(?:\S*\[dot\]\S*)|(?:\S*hxxp\S*))`)
)

// Parse parses emails from RiskIQ
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, common.NewParserError("subject not found")
	}
	subject = strings.ReplaceAll(strings.ReplaceAll(subject, "\r", ""), "\n", "")

	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("body not found")
	}

	// Route to appropriate parser based on subject
	if strings.Contains(subject, "PHISHING") ||
		strings.Contains(subject, "Unlawful Credential Distribution-Financial Data") ||
		strings.Contains(subject, "Suspected Phish Attempt") {
		return parseGeneralType(serializedEmail)
	} else if strings.Contains(subject, "URGENT") ||
		strings.Contains(subject, "TIME-SENSITIVE – Malicious Phishing Domain Name Registration") {
		return parsePhishingSimpleType(serializedEmail)
	} else if strings.Contains(subject, "Notice of Claimed Infringement") {
		return parseCopyrightTextType(serializedEmail, subject, body)
	} else if strings.Contains(subject, "Unauthorized Use of WESTERN UNION® Marks") {
		return parseBrandProtection(serializedEmail, subject, body)
	} else if strings.Contains(subject, "TIME-SENSITIVE – Malicious Domain Name Re-direction") {
		return parsePhishingRedirection(serializedEmail, body)
	} else if strings.Contains(subject, "TIME-SENSITIVE – Registered and Used in Bad Faith") {
		return parseBadFaith(serializedEmail, body)
	} else if strings.Contains(subject, "TIME-SENSITIVE – Malicious Phishing Domain Name Registration") {
		return parsePhishingRegistration(serializedEmail, body)
	} else if strings.Contains(subject, "Unauthorised Direct Download") ||
		strings.Contains(subject, "Unauthorized Direct Download") {
		return parseDirectDownload(serializedEmail, body)
	} else if strings.Contains(subject, "Notification of Claimed Infringement") {
		return parseTrademark(serializedEmail, body)
	} else if strings.Contains(subject, "From RISKIQ on behalf of") {
		return parseTrademarkSummary(serializedEmail, body)
	} else if strings.Contains(subject, "Severity High / ") {
		return parseTrademarkSummary(serializedEmail, body)
	} else if strings.Contains(subject, "Notice of Prohibited Content") {
		return parseProhibitedContent(serializedEmail, body)
	} else if strings.Contains(subject, "Privacy Interference on Your System or Network") {
		return parseDoxing(serializedEmail, body)
	} else if strings.Contains(subject, "Malware") {
		return parseMalware(serializedEmail, body)
	} else if strings.Contains(subject, "Formal Notice of Email Spoof") {
		return parsePhishingSimpleType(serializedEmail)
	} else if strings.Contains(subject, "Phishing Materials on") {
		return parsePhishingDefanged(serializedEmail, body, subject)
	} else if strings.Contains(subject, "Phishing Materials Utilising") ||
		strings.Contains(subject, "Harmful Cyber Operation") {
		return parsePhishingAndFraud(body, subject)
	} else if strings.Contains(subject, "Copyright Infringement") {
		return parseAbusiveContent(body, subject)
	} else if strings.Contains(subject, "Malicious Phishing Domain Name Registration") {
		return parseMaliciousPhishingDomainNameRegistration(body)
	}

	return nil, common.NewNewTypeError(subject)
}

func eventSetup(serializedEmail *email.SerializedEmail) *events.Event {
	event := events.NewEvent("riskiq")
	event.SenderEmail = "irt@riskiq.net"
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}
	return event
}

func getEventType(line string) (events.EventType, string, error) {
	lineLower := strings.ToLower(line)
	if strings.Contains(line, "Network Hosted Phishing") || strings.Contains(lineLower, "phishing") {
		return events.NewPhishing(), "phishing_url", nil
	} else if strings.Contains(line, "Unlawful Credential Distribution – Financial Data") {
		return events.NewFraud(), "distribution_url", nil
	} else if strings.Contains(line, "Malicious Domain Redirection Using Your Network") {
		return events.NewPhishing(), "redirection_url", nil
	}
	return nil, "", common.NewNewTypeError(line)
}

func parseBody(body string, date *time.Time, urlKey string) ([]*events.Event, error) {
	var evts []*events.Event
	urlSet := make(map[string]bool)
	lines := strings.Split(body, "\n")
	var targetBrand string
	var ip string
	var eventType events.EventType
	var asn string

	if urlKey != "" {
		var err error
		eventType, _, err = getEventType(urlKey)
		if err != nil {
			return nil, err
		}
	}

	for i, line := range lines {
		if strings.Contains(line, "hxxp") || (strings.Contains(line, "[dot]") && !strings.Contains(line, "[at]")) {
			if match := urlGobbler.FindStringSubmatch(line); len(match) > 0 {
				url := strings.Trim(match[0], ",[]()")
				urlSet[url] = true
			}
		} else if strings.Contains(line, "Target Brand:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				targetBrand = strings.ReplaceAll(strings.TrimSpace(parts[1]), "\n", "")
			}
		} else if strings.Contains(line, "IP Address:") {
			ip = common.ExtractOneIP(line)
			ip = common.IsIP(ip)
			if ip == "" && i+1 < len(lines) {
				ip = common.ExtractOneIP(lines[i+1])
			}
		} else if strings.Contains(line, "ASN:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				asn = strings.ReplaceAll(strings.TrimSpace(parts[1]), "\n", "")
			}
		} else if strings.Contains(line, "Event Type:") {
			var err error
			eventType, _, err = getEventType(line)
			if err != nil {
				return nil, err
			}
		}
	}

	if urlKey == "" {
		eventType, _, _ = getEventType("Phishing")
	}

	for url := range urlSet {
		event := events.NewEvent("riskiq")
		event.EventDate = date
		event.IP = ip
		event.URL = url
		if targetBrand != "" {
			event.AddEventDetail(&events.Target{Brand: targetBrand})
		}
		event.EventTypes = []events.EventType{eventType}
		if asn != "" {
			event.AddEventDetail(&events.ASN{ASN: asn})
		}
		evts = append(evts, event)
	}

	return evts, nil
}

func parseGeneralType(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	var date *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		date = email.ParseDate(dateHeaders[0])
	}
	return parseBody(body, date, "")
}

func getDeepestBody(serializedEmail *email.SerializedEmail) string {
	// Simplified implementation - just get the first text part
	if len(serializedEmail.Parts) > 0 {
		// Try to find the first part with body
		for _, part := range serializedEmail.Parts {
			if str, ok := part.Body.(string); ok && str != "" {
				return str
			}
		}
	}

	// Fallback to body
	if body, ok := serializedEmail.Body.(string); ok {
		return body
	}
	return ""
}

func parsePhishingSimpleType(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body := getDeepestBody(serializedEmail)
	var date *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		date = email.ParseDate(dateHeaders[0])
	}
	return parseBody(body, date, "phishing_url")
}

func parseCopyrightTextType(serializedEmail *email.SerializedEmail, subject, body string) ([]*events.Event, error) {
	event := eventSetup(serializedEmail)
	eventType := &events.Copyright{}

	// Extract infringing URL from subject
	subjectCleaned := strings.ReplaceAll(subject, "[dot]", ".")
	parts := strings.Split(subjectCleaned, " ")
	if len(parts) > 0 {
		lastPart := parts[len(parts)-1]
		if domain := extractOneDomain(lastPart); domain != "" {
			event.URL = domain
		}
	}

	// Extract owner
	if match := ownerRegex.FindStringSubmatch(body); len(match) > 1 {
		eventType.CopyrightOwner = strings.TrimSpace(match[1])
	}

	// Extract trademark
	if match := trademarkRegex.FindStringSubmatch(body); len(match) > 1 {
		eventType.CopyrightedWork = strings.ReplaceAll(strings.TrimSpace(match[1]), "\n", "")
	}

	event.EventTypes = []events.EventType{eventType}
	return []*events.Event{event}, nil
}

func parseBrandProtection(serializedEmail *email.SerializedEmail, subject, body string) ([]*events.Event, error) {
	event := eventSetup(serializedEmail)
	eventType := &events.Copyright{}
	var domain string

	// Extract copyrighted work from subject
	parts := strings.Split(subject, ":")
	if len(parts) > 0 {
		lastPart := parts[len(parts)-1]
		workParts := strings.Split(lastPart, "at")
		if len(workParts) > 0 {
			eventType.CopyrightedWork = strings.ReplaceAll(strings.TrimSpace(workParts[0]), "\n", "")
		}
	}

	// Parse key-value pairs
	kvPairs := common.OneLineColonKeyValueGenerator(body)
	for key, values := range kvPairs {
		if len(values) == 0 {
			continue
		}
		value := values[0]
		if key == "Url" {
			event.URL = value
		} else if key == "Domain" {
			domain = value
		} else if key == "IP Address" {
			event.IP = value
		}
	}

	if event.URL == "" {
		event.URL = domain
	}

	event.EventTypes = []events.EventType{eventType}
	return []*events.Event{event}, nil
}

func parsePhishingRedirection(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	event := eventSetup(serializedEmail)
	eventType := events.NewPhishing()
	target := &events.Target{}
	lines := strings.Split(body, "\n")

	for i, line := range lines {
		if strings.Contains(line, "Target Brand") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				target.Brand = strings.ReplaceAll(strings.TrimSpace(parts[1]), "\n", "")
			}
		} else if strings.Contains(line, "Domain Registrar") {
			parts := strings.Split(line, ": ")
			if len(parts) > 0 {
				event.AddEventDetail(&events.Organisation{
					Name:         "domain_registrar",
					Organisation: parts[len(parts)-1],
				})
			}
		} else if strings.Contains(line, `"ip"`) {
			ip := common.ExtractOneIP(line)
			target.IP = ip
		}
		_ = i
	}

	// Find artifacts
	data := common.FindString(body, "Artificats:\r\n\r\n", "\r\n\r\n")
	if data == "" {
		data = common.FindString(body, "Artificats:\n\n", "\n\n")
	}
	if data == "" {
		return nil, common.NewParserError("data part not found")
	}

	data = strings.TrimPrefix(data, "Artificats:\r\n\r\n")
	data = strings.TrimPrefix(data, "Artificats:\n\n")
	data = strings.ReplaceAll(data, "[dot]", ".")
	data = strings.ReplaceAll(data, "[.]", ".")
	data = strings.ReplaceAll(data, "\r\n", "")
	data = strings.ReplaceAll(data, "\n", "")
	data = strings.Trim(data, " ,\r\n")

	// Extract URL
	url := common.FindStringWithoutMarkers(data, `:"`, `"`)
	event.URL = url
	eventType.PhishingTarget = url
	event.EventTypes = []events.EventType{eventType}

	// Extract redirection details
	dataSplit := strings.Split(data, " ")
	if len(dataSplit) > 0 {
		urlParts := strings.Split(dataSplit[0], "//")
		if len(urlParts) > 1 {
			redirectionURL := "http://" + urlParts[1]
			event.AddEventDetailSimple("redirection_url", redirectionURL)
		}
	}
	if len(dataSplit) > 2 {
		event.IP = dataSplit[2]
	}

	return []*events.Event{event}, nil
}

func parseBadFaith(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	event := eventSetup(serializedEmail)
	eventType := &events.Trademark{}

	linebreak := "\n"
	if strings.Contains(body, "\r\n") {
		linebreak = "\r\n"
	}

	authorization := common.FindStringWithoutMarkers(body, "We are the authorized agent for", "."+linebreak)
	if authorization == "" {
		return nil, common.NewParserError("missing complainant")
	}
	eventType.TrademarkOwner = strings.TrimSpace(authorization)

	// Parse key-value pairs
	kvPairs := common.OneLineColonKeyValueGenerator(body)
	for key, values := range kvPairs {
		if key == "Website" && len(values) > 0 {
			event.URL = values[0]
			break
		}
	}

	event.EventTypes = []events.EventType{eventType}
	return []*events.Event{event}, nil
}

func parsePhishingRegistration(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	event := eventSetup(serializedEmail)
	var urls []string
	lines := strings.Split(body, "\n")

	for i, line := range lines {
		if strings.HasPrefix(line, "<") {
			continue
		}

		if strings.Contains(line, "Target Brand") && i+2 < len(lines) {
			event.AddEventDetail(&events.Target{Brand: lines[i+2]})
		} else if strings.Contains(line, "Domain Name(s)") && i+2 < len(lines) {
			domain := strings.Split(lines[i+2], "(")[0]
			domain = strings.ReplaceAll(strings.TrimSpace(domain), "[dot]", ".")
			event.AddEventDetailSimple("domain", domain)
		} else if strings.Contains(line, "Domain Registrar") && i+2 < len(lines) {
			event.AddEventDetailSimple("domain_registrar", lines[i+2])
		} else if strings.Contains(line, "IP Address") && i+2 < len(lines) {
			event.IP = lines[i+2]
		} else if strings.Contains(line, "URL(s)") {
			urlData := common.FindStringWithoutMarkers(body, "URL(s)", "(")
			urlData = strings.ReplaceAll(urlData, "\r", "\n")
			for _, urlLine := range strings.Split(urlData, "\n") {
				if strings.HasPrefix(urlLine, "h") {
					urls = append(urls, urlLine)
				}
			}
		}
	}

	if len(urls) > 0 {
		phishing := events.NewPhishing()
		phishing.PhishingTarget = urls[0]
		event.EventTypes = []events.EventType{phishing}
		event.URL = urls[0]
	}

	return []*events.Event{event}, nil
}

func parseDirectDownload(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	event := eventSetup(serializedEmail)
	eventType := &events.Copyright{}

	linebreak := "\n"
	if strings.Contains(body, "\r\n") {
		linebreak = "\r\n"
	}

	work := common.FindStringWithoutMarkers(body, "Infringing Application Name:", "")
	eventType.CopyrightedWork = strings.ReplaceAll(strings.TrimSpace(work), "\n", "")

	owner := common.FindStringWithoutMarkers(body, "Developer Name:", "")
	eventType.CopyrightOwner = strings.TrimSpace(owner)

	url := common.FindStringWithoutMarkers(body, "Application Store Link:", linebreak+linebreak)
	if url == "" {
		return nil, common.NewParserError("no url found")
	}

	event.URL = url
	event.EventTypes = []events.EventType{eventType}
	return []*events.Event{event}, nil
}

func parseAbusiveContent(body, subject string) ([]*events.Event, error) {
	externalID := strings.TrimSpace(strings.Split(subject, "- Incident ")[len(strings.Split(subject, "- Incident "))-1])

	var date *time.Time
	var ip string
	urlSet := make(map[string]bool)

	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, "Date and Time") {
			dateStr := strings.TrimSpace(strings.Split(line, "*:")[len(strings.Split(line, "*:"))-1])
			dateStr = strings.ReplaceAll(strings.ReplaceAll(dateStr, "PM ", ""), "AM ", "")
			date = email.ParseDate(dateStr)
		} else if strings.Contains(line, "IP Address") {
			ip = strings.TrimSpace(strings.Split(line, ":")[len(strings.Split(line, ":"))-1])
		} else if strings.Contains(line, "hxxp") {
			urlSet[line] = true
		}
	}

	originalURL := strings.TrimSpace(common.FindStringWithoutMarkers(body, "software applications available at", " "))
	owner := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Identification of the Copyrighted Work*", "and its"))

	var evts []*events.Event
	for url := range urlSet {
		event := events.NewEvent("riskiq")
		event.EventDate = date
		event.URL = url
		event.IP = ip
		event.AddEventDetail(&events.ExternalID{ID: externalID})
		event.EventTypes = []events.EventType{&events.Copyright{
			OfficialURL:    originalURL,
			CopyrightOwner: strings.TrimSpace(owner),
		}}
		evts = append(evts, event)
	}

	return evts, nil
}

func parseDoxing(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	event := eventSetup(serializedEmail)
	event.EventTypes = []events.EventType{events.NewDoxing()}

	nameServers := make(map[string]bool)
	var url string
	hasIP := false
	lines := strings.Split(body, "\n")

	for i, line := range lines {
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) < 2 {
			continue
		}
		key := strings.ToLower(parts[0])
		value := parts[1]

		if strings.Contains(key, "name server") {
			combined := value
			if i+1 < len(lines) {
				combined = strings.TrimSpace(value + " " + strings.ReplaceAll(lines[i+1], "\n", " "))
			}
			if combined != "" {
				nameServers[combined] = true
			}
		} else if strings.Contains(key, "a record") {
			event.IP = value
			hasIP = true
		} else if strings.Contains(key, "threat activity type") {
			if !strings.Contains(strings.ToLower(value), "doxxing") {
				return nil, common.NewNewTypeError(value)
			}
		} else if strings.Contains(key, "location") {
			urlParts := strings.Split(value, " ")
			if len(urlParts) > 0 {
				url = urlParts[0]
				event.URL = url
			}
		}

		if url != "" && len(nameServers) > 0 && hasIP {
			break
		}
	}

	// Add name servers as evidence
	if len(nameServers) > 0 {
		evidence := &events.Evidence{}
		for ns := range nameServers {
			evidence.AddEvidence(events.UrlStore{Description: "name_server", URL: ns})
		}
		event.AddEventDetail(evidence)
	}

	if url == "" {
		return nil, common.NewParserError("required information not found")
	}

	return []*events.Event{event}, nil
}

func parseProhibitedContent(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	event := eventSetup(serializedEmail)
	eventType := &events.Trademark{}

	asset := common.GetNonEmptyLineAfter(body, "Location of Prohibited Content")
	assetParts := strings.Split(strings.TrimSpace(asset), " ")
	if len(assetParts) == 0 || assetParts[0] == "" {
		return nil, common.NewParserError("missing url")
	}
	event.URL = assetParts[0]

	authorizer := common.FindStringWithoutMarkers(body, "3. *", "Intellectual Property Rights")
	if authorizer != "" {
		eventType.TrademarkOwner = strings.TrimSpace(authorizer)
	}

	moreData := common.GetNonEmptyLineAfter(body, "Technical Details for the Prohibited Content")
	ipParts := strings.SplitN(moreData, "/ ASN:", 2)
	event.IP = ipParts[0]

	if len(ipParts) > 1 {
		asn := strings.ReplaceAll(strings.TrimSpace(ipParts[1]), "\n", "")
		event.AddEventDetail(&events.ASN{ASN: asn})
	}

	event.EventTypes = []events.EventType{eventType}
	return []*events.Event{event}, nil
}

func parseTrademark(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	event := eventSetup(serializedEmail)
	eventType := &events.Trademark{}
	var asset string
	lines := strings.Split(body, "\n")
	foundTrademark := false
	var trademarkMaterial string

	for i, line := range lines {
		if foundTrademark && asset != "" {
			break
		}

		if !foundTrademark {
			var value string
			if strings.Contains(line, "Infringing Application Name") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) > 1 {
					value = strings.TrimSpace(parts[1])
				}
			} else if strings.Contains(line, `"`) {
				value = common.FindStringWithoutMarkers(line, `"`, `"`)
			}
			if value != "" {
				foundTrademark = true
				trademarkMaterial = value
			}
		}

		if asset == "" {
			if strings.Contains(line, "Application Store Link") && i+1 < len(lines) {
				asset = strings.TrimSpace(lines[i+1])
			} else if strings.Contains(line, "Infringing digital asset") && i+2 < len(lines) {
				asset = strings.TrimSpace(lines[i+2])
			} else if strings.Contains(line, "Infringing URL") && i+1 < len(lines) {
				asset = strings.TrimSpace(lines[i+1])
			} else if strings.Contains(line, "visible or hidden text on the web site") && i+1 < len(lines) {
				assetParts := strings.Split(strings.TrimSpace(lines[i+1]), " ")
				if len(assetParts) > 0 {
					asset = assetParts[0]
				}
			}
		}
	}

	if asset == "" {
		return nil, common.NewParserError("missing asset url")
	}
	event.URL = strings.Trim(asset, "()[],")

	// Find authorizer
	authorizeStrings := [][]string{
		{"on behalf of ", ", "},
		{"has been engaged by ", "as its authorized"},
		{`"`, `"`},
	}
	var authorizer string
	for _, markers := range authorizeStrings {
		authorizer = common.FindStringWithoutMarkers(body, markers[0], markers[1])
		if authorizer != "" {
			break
		}
	}
	if authorizer == "" {
		return nil, common.NewParserError("missing complainant")
	}
	eventType.TrademarkOwner = authorizer
	eventType.TrademarkedMaterial = trademarkMaterial
	event.EventTypes = []events.EventType{eventType}

	return []*events.Event{event}, nil
}

func parseTrademarkSummary(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	var evts []*events.Event
	urlsData := common.FindStringWithoutMarkers(body, "URL(s):", "(collectively")
	urlLines := strings.Split(strings.TrimSpace(urlsData), "\n")
	urlSet := make(map[string]bool)
	for _, url := range urlLines {
		url = strings.TrimSpace(url)
		if url != "" {
			urlSet[url] = true
		}
	}

	owner := strings.TrimSpace(strings.Trim(common.FindStringWithoutMarkers(body, "Trademark Owner:", ""), ";"))
	ip := strings.TrimSpace(strings.Trim(common.FindStringWithoutMarkers(body, "IP Address", ""), ";"))

	for url := range urlSet {
		event := eventSetup(serializedEmail)
		eventType := &events.Trademark{}
		if owner != "" {
			eventType.TrademarkOwner = owner
		}
		event.IP = ip
		event.URL = url
		event.EventTypes = []events.EventType{eventType}
		evts = append(evts, event)
	}

	return evts, nil
}

func parseMalware(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	event := eventSetup(serializedEmail)

	domain := common.FindStringWithoutMarkers(body, "located at ", " ")
	url := strings.Trim(common.FindStringWithoutMarkers(body, domain, ")"), "()[], ")
	event.URL = url

	trademarkParts := strings.Split(common.FindStringWithoutMarkers(body, "trademark", ","), `"`)
	var trademarkHolder string
	if len(trademarkParts) > 1 {
		trademarkHolder = trademarkParts[1]
	}

	if strings.Contains(body, "trademarks are used") {
		event.EventTypes = []events.EventType{
			&events.Trademark{TrademarkOwner: trademarkHolder},
			&events.Phishing{PhishingTarget: url},
		}
	} else {
		return nil, common.NewNewTypeError("type not found")
	}

	return []*events.Event{event}, nil
}

func parsePhishingDefanged(serializedEmail *email.SerializedEmail, body, subject string) ([]*events.Event, error) {
	event := eventSetup(serializedEmail)

	lines := common.GetContinuousLinesUntilEmptyLine(body, "Location of Phishing")
	var phishingURL string
	if len(lines) > 0 {
		phishingURL = lines[0]
	}

	phishing := events.NewPhishing()
	phishing.PhishingTarget = phishingURL
	event.EventTypes = []events.EventType{phishing}

	event.IP = common.FindStringWithoutMarkers(body, "IP Address", "")
	asn := strings.TrimSpace(common.FindStringWithoutMarkers(body, "ASN*:", ""))
	event.AddEventDetail(&events.ASN{ASN: asn})

	brand := strings.TrimSpace(common.FindStringWithoutMarkers(body, "spoofed Brand*:", ""))
	event.AddEventDetail(&events.Target{Brand: brand})

	externalID := common.FindStringWithoutMarkers(subject, "Incident ID: ", " ")
	event.AddEventDetail(&events.ExternalID{ID: externalID})

	return []*events.Event{event}, nil
}

func parsePhishingAndFraud(body, subject string) ([]*events.Event, error) {
	urlData := common.FindStringWithoutMarkers(body, "*IP Address*", "*****")
	var urls []string
	for _, line := range strings.Split(urlData, "\n") {
		if strings.HasPrefix(line, "hxxp") {
			urls = append(urls, line)
		}
	}

	id := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Incident ID", ""))
	ip := common.GetNonEmptyLineAfter(body, "IP Address*")
	asn := strings.ReplaceAll(common.GetNonEmptyLineAfter(body, "*ASN*"), "\n", "")

	dateStr := strings.TrimSpace(common.GetNonEmptyLineAfter(body, "Date and Time"))
	dateStr = strings.ReplaceAll(strings.ReplaceAll(dateStr, "AM ", ""), "PM ", "")
	if dateStr == "" {
		dateStr = strings.TrimSpace(common.GetNonEmptyLineAfter(body, "*Date Event Created*"))
		dateStr = strings.ReplaceAll(dateStr, ",", " 00:00:00")
	}

	var evts []*events.Event
	for _, url := range urls {
		event := events.NewEvent("riskiq")
		event.IP = ip
		event.URL = url
		event.EventDate = email.ParseDate(dateStr)

		if strings.Contains(subject, "Phishing") {
			phishing := events.NewPhishing()
			phishing.PhishingTarget = url
			event.EventTypes = []events.EventType{phishing}
		} else if strings.Contains(subject, "Harmful Cyber") {
			event.EventTypes = []events.EventType{events.NewFraud()}
		}

		event.AddEventDetail(&events.ASN{ASN: asn})
		event.AddEventDetail(&events.ExternalID{ID: id})
		evts = append(evts, event)
	}

	return evts, nil
}

func parseMaliciousPhishingDomainNameRegistration(body string) ([]*events.Event, error) {
	var evts []*events.Event
	urlSet := make(map[string]bool)

	brand := common.FindStringWithoutMarkers(body, "Brand:", "")
	dateStr := common.FindStringWithoutMarkers(body, "Date and Time of Abuse:", "")
	ip := common.FindStringWithoutMarkers(body, "IP Address:", "")

	onBehalfParts := strings.Split(common.FindStringWithoutMarkers(body, "We write for", ""), "(")
	organization := &events.OnBehalfOf{}
	if len(onBehalfParts) > 0 {
		organization.ComplainantContact = strings.TrimSpace(onBehalfParts[0])
	}
	if len(onBehalfParts) > 1 {
		urlPart := strings.Split(onBehalfParts[1], ")")[0]
		organization.ComplainantEmail = strings.TrimSpace(urlPart)
	}

	externalID := &events.ExternalID{ID: strings.TrimSpace(common.FindStringWithoutMarkers(body, "Incident No.", ""))}

	urlData := common.FindStringWithoutMarkers(body, "URL(s):", "")
	firstURL := strings.Split(strings.TrimSpace(urlData), "<")[0]
	urlSet[firstURL] = true

	hxxpRegex := regexp.MustCompile(`hxxp.*`)
	for _, match := range hxxpRegex.FindAllString(body, -1) {
		url := strings.Split(strings.Split(match, "<")[0], "?")[0]
		url = strings.TrimSpace(url)
		if url != "" {
			urlSet[url] = true
		}
	}

	for url := range urlSet {
		if url == "" {
			continue
		}
		event := events.NewEvent("riskiq")
		phishing := events.NewPhishing()
		phishing.PhishingTarget = url
		event.EventTypes = []events.EventType{phishing}
		event.AddEventDetail(&events.Target{Brand: brand})
		event.AddEventDetail(organization)
		event.AddEventDetail(externalID)
		event.EventDate = email.ParseDate(dateStr)
		event.URL = url
		event.IP = ip
		evts = append(evts, event)
	}

	return evts, nil
}

// Helper function to extract domain (simplified)
func extractOneDomain(text string) string {
	// Basic domain extraction - look for pattern like domain.com
	domainRegex := regexp.MustCompile(`(?i)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}`)
	if match := domainRegex.FindString(text); match != "" {
		return match
	}
	return ""
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
