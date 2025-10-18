package phishlabscom

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

var (
	httpSpaceGadget = regexp.MustCompile(`h(xx|tt)p(?P<ssl>s?)\s?(://)?`)
	spaceBeforeTLD  = regexp.MustCompile(`\s(?=[.]\S)`)
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Get from address for routing logic
	fromAddr, _ := common.GetFrom(serializedEmail, false)
	subject = strings.ReplaceAll(subject, "\n", " ")

	var eventsList []*events.Event

	// Route based on sender
	if fromAddr == "mitigation@phishlabs.com" {
		eventsList = parsePhishlabsMitigation(serializedEmail, body)
	} else if fromAddr == "tms@phishlabs.com" && (strings.Contains(strings.ToLower(subject), "unauthorized use") || strings.Contains(strings.ToLower(subject), "action request")) {
		eventsList = parsePhishlabsTMS(serializedEmail, body, subject)
	} else if fromAddr == "abuse@linode.com" && strings.Contains(body, "tms@phishlabs.com") {
		eventsList = parsePhishlabsTMS(serializedEmail, body, subject)
	} else {
		subjectLower := strings.ToLower(strings.TrimSpace(subject))
		if strings.Contains(subjectLower, "malware infrastructure hosted") {
			eventsList = parseMalwareInfrastructure(serializedEmail, body, subject)
		} else if strings.Contains(subjectLower, "mobile application") {
			eventsList = parseMobileApplication(serializedEmail, body)
		} else if strings.Contains(subjectLower, "fraudulent") {
			eventsList = parseFraudulentUse(serializedEmail, body)
		} else {
			eventsList = parsePhishing(serializedEmail, body, subject)
		}
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return eventsList, nil
}

func fillEventWithGenericData(serializedEmail *email.SerializedEmail, body string, event *events.Event) int {
	startIndex := -1
	firstSeen := false
	var eventDate *time.Time
	hostnameServer := false

	lines := strings.Split(body, "\n")
	for number, line := range lines {
		if line == "" {
			continue
		}

		if !firstSeen && strings.Contains(line, "First detection of malicious activity") {
			eventDate = parseMagicDateTime(line)
			firstSeen = true
			if eventDate != nil {
				event.AddEventDetailSimple("first_seen", eventDate)
			}
		} else if event.EventDate == nil && strings.Contains(line, "Most recent observation of malicious activity") {
			eventDate = parseMagicDateTime(line)
			event.EventDate = eventDate
		} else if event.IP == "" && strings.Contains(line, "Associated IP Address") {
			// Merge current line with next line
			mergedLine := line
			if number+1 < len(lines) {
				mergedLine = line + " " + lines[number+1]
			}
			mergedLine = strings.ReplaceAll(mergedLine, "[", "")
			mergedLine = strings.ReplaceAll(mergedLine, "]", "")

			if ip := common.ExtractOneIP(mergedLine); ip != "" {
				if validIP := common.IsIP(ip); validIP != "" {
					event.IP = validIP
				}
			}
		} else if !hostnameServer && strings.Contains(line, "Hostname of Server") {
			parts := strings.SplitN(line, ": ", 2)
			if len(parts) == 2 {
				hostname := parts[1]
				hostname = strings.ReplaceAll(hostname, "[", "")
				hostname = strings.ReplaceAll(hostname, "]", "")
				hostname = strings.ReplaceAll(hostname, " .", ".")
				hostname = spaceBeforeTLD.ReplaceAllString(hostname, "")

				if hostname != "" {
					hostnameServer = true
					if event.URL == "" {
						event.URL = hostname
					}
				}
			}
		} else {
			continue
		}

		if startIndex == -1 {
			startIndex = number
		}
	}

	// Default to email date if no event date found
	if eventDate == nil {
		if headers := serializedEmail.Headers; headers != nil {
			if dateHeaders := headers["date"]; len(dateHeaders) > 0 {
				event.EventDate = email.ParseDate(dateHeaders[0])
			}
		}
	}

	return startIndex
}

func deepSplit(data string, tools []string, splitAtLinebreak bool) []string {
	var lines []string
	if splitAtLinebreak {
		lines = strings.Split(data, "\n")
	} else {
		lines = []string{data}
	}

	result := make([]string, 0)
	for _, tool := range tools {
		temp := make([]string, 0)
		for _, line := range lines {
			parts := strings.Split(strings.ReplaceAll(line, tool, "^$^"+tool), "^$^")
			temp = append(temp, parts...)
		}
		lines = temp
	}

	return append(result, lines...)
}

func parsePhishing(serializedEmail *email.SerializedEmail, body, subject string) []*events.Event {
	var eventsList []*events.Event
	var ip string
	var urlTemplate string

	if strings.Contains(subject, "hosted on") {
		urlTemplate = strings.TrimSpace(strings.Trim(common.FindStringWithoutMarkers(subject+"\n", "hosted on", ""), " :"))
	}

	event := events.NewEvent("phishlabscom")
	endIndex := fillEventWithGenericData(serializedEmail, body, event)

	urls := make(map[string]bool)

	// Try to find simple URL guess
	simpleURLGuess := strings.TrimSpace(strings.Trim(common.FindStringWithoutMarkers(body, "Typo Squatting Domain to be Investigated", ""), " ."))
	if simpleURLGuess == "" {
		simpleURLGuess = strings.TrimSpace(common.FindStringWithoutMarkers(body, "behalf of other organizations.", "We kindly request"))
	}
	if simpleURLGuess != "" {
		urls[simpleURLGuess] = true
	}

	// Try to find IP if not already set
	if event.IP == "" {
		simpleIPGuess := common.FindStringWithoutMarkers(body, "IP Address", "")
		if simpleIPGuess != "" {
			if extractedIP := common.ExtractOneIP(simpleIPGuess); extractedIP != "" {
				if validIP := common.IsIP(extractedIP); validIP != "" {
					event.IP = validIP
					ip = validIP
				}
			}
		}
	}

	// Find URLs based on template or scan body
	domainBlockStarted := false
	if urlTemplate != "" {
		urlTemplate = strings.ReplaceAll(urlTemplate, "hxxp", "http")
		bodyLower := strings.ToLower(body)
		bodyLower = strings.ReplaceAll(bodyLower, " [dot] ", ".")
		bodyLower = httpSpaceGadget.ReplaceAllString(bodyLower, "http$2://")

		lines := deepSplit(bodyLower, []string{"http"}, true)
		for _, urlLine := range lines {
			if strings.Contains(urlLine, "http") && strings.Contains(urlLine, urlTemplate) {
				parts := strings.Fields(urlLine)
				if len(parts) > 0 {
					urls[parts[0]] = true
				}
			}
		}
	} else {
		lines := strings.Split(body, "\n")
		if endIndex > 0 && endIndex < len(lines) {
			// Reverse iterate through lines before endIndex
			for i := endIndex - 1; i >= 0; i-- {
				line := lines[i]
				lineLower := strings.ToLower(line)
				if strings.Contains(lineLower, "hxxp") || strings.Contains(lineLower, "http") {
					if strings.Contains(line, "phishlabs") {
						continue
					}
					domainBlockStarted = true
					cleanedURL := strings.ReplaceAll(line, " .", ".")
					urls[cleanedURL] = true
				} else if domainBlockStarted {
					break
				}
			}
		}
	}

	// Last resort URL finding
	if len(urls) == 0 {
		lastResort := strings.TrimSpace(common.FindStringWithoutMarkers(body, "behalf of other organizations.", "We kindly request"))
		if lastResort != "" {
			urls[lastResort] = true
		} else {
			// No URLs found - return empty list
			return eventsList
		}
	}

	// Create events for each URL
	for urlStr := range urls {
		newEvent := events.NewEvent("phishlabscom")
		newEvent.URL = urlStr
		fillEventWithGenericData(serializedEmail, body, newEvent)

		if newEvent.IP == "" {
			newEvent.IP = ip
		}

		phishing := events.NewPhishing()
		phishing.PhishingTarget = urlStr
		newEvent.EventTypes = []events.EventType{phishing}

		// Use first_seen as event date if event_date is empty
		if newEvent.EventDate == nil {
			for _, detail := range newEvent.EventDetails {
				if simple, ok := detail.(*events.SimpleDetail); ok {
					if simple.Key == "first_seen" {
						if ts, ok := simple.Value.(*time.Time); ok {
							newEvent.EventDate = ts
						}
					}
				}
			}
		}

		eventsList = append(eventsList, newEvent)
	}

	return eventsList
}

func parseMalwareInfrastructure(serializedEmail *email.SerializedEmail, body, subject string) []*events.Event {
	var eventsList []*events.Event
	var linkURL, payloadURL string
	var oldDate *time.Time

	// Extract IP from subject
	ip := common.ExtractOneIP(subject)
	if ip != "" {
		ip = common.IsIP(ip)
	}

	domains := make(map[string]map[string]bool)
	domainStartIndex := 0

	lines := strings.Split(body, "\n")
	for number, line := range lines {
		if oldDate == nil && strings.Contains(line, "via the abuse webform") {
			oldDate = parseMagicDateTime(line)
		}

		// Get IP and source URL
		if ip == "" && strings.Contains(line, "===============") {
			if number+2 < len(lines) {
				extractedIP := common.ExtractOneIP(lines[number+1])
				if extractedIP != "" {
					ip = common.IsIP(extractedIP)
				}

				urlLine := lines[number+2]
				domain := extractDomain(urlLine)
				if domain != "" {
					if domains[domain] == nil {
						domains[domain] = make(map[string]bool)
					}
					domains[domain][urlLine] = true
				}
			}
		}

		// Get evidence
		if strings.Contains(line, "Evidence:") {
			if number+4 < len(lines) {
				linkURL = strings.ReplaceAll(lines[number+2], "hXXp", "http")
				payloadURL = strings.ReplaceAll(lines[number+4], "hXXp", "http")
			}
			break
		}

		if domainStartIndex > 0 && number >= domainStartIndex {
			if strings.TrimSpace(line) != "" {
				domain := extractDomain(line)
				if domain != "" {
					if domains[domain] == nil {
						domains[domain] = make(map[string]bool)
					}
					domains[domain][line] = true
				}
			} else {
				break // Empty line - no more information
			}
		}

		// Detect domain block start
		if domainStartIndex == 0 {
			if (strings.Contains(line, "malware campaign:") && (number+2 >= len(lines) || !strings.Contains(lines[number+2], "MALWARE DROP:"))) ||
				strings.Contains(line, "command and control server") {
				domainStartIndex = number + 2
			}
		}
	}

	// Create events for each domain/URL combination
	for _, urlSet := range domains {
		for urlStr := range urlSet {
			var port int
			evidence := &events.Evidence{}

			// Extract port from URL (format: proto://host:port/path)
			parts := strings.Split(urlStr, ":")
			if len(parts) >= 3 {
				portParts := strings.Split(parts[2], "/")
				if len(portParts) > 0 {
					if p, err := strconv.Atoi(portParts[0]); err == nil {
						port = p
					}
				}
			}

			cleanURL := strings.ReplaceAll(urlStr, "hXXp", "http")

			event := events.NewEvent("phishlabscom")
			if headers := serializedEmail.Headers; headers != nil {
				if dateHeaders := headers["date"]; len(dateHeaders) > 0 {
					event.EventDate = email.ParseDate(dateHeaders[0])
				}
			}

			event.EventTypes = []events.EventType{events.NewMalware("")}
			event.IP = ip

			if oldDate != nil {
				event.AddEventDetailSimple("first_seen", oldDate)
			}

			if linkURL != "" {
				evidence.AddEvidence(events.UrlStore{
					Description: "link_analysis",
					URL:         linkURL,
				})
			}
			if payloadURL != "" {
				evidence.AddEvidence(events.UrlStore{
					Description: "payload_analysis",
					URL:         payloadURL,
				})
			}
			if len(evidence.URLs) > 0 {
				event.AddEventDetail(evidence)
			}

			event.URL = cleanURL
			// Check if URL is actually an IP
			if extractedIP := common.ExtractOneIP(cleanURL); extractedIP != "" {
				event.IP = cleanURL
			}

			event.Port = port
			eventsList = append(eventsList, event)
		}
	}

	return eventsList
}

func parseMobileApplication(serializedEmail *email.SerializedEmail, body string) []*events.Event {
	var eventsList []*events.Event

	urls := common.GetContinuousLinesUntilEmptyLine(body, "hosted under your control:")
	urlSet := make(map[string]bool)
	for _, u := range urls {
		urlSet[u] = true
	}

	var eventDate *time.Time
	if headers := serializedEmail.Headers; headers != nil {
		if dateHeaders := headers["date"]; len(dateHeaders) > 0 {
			eventDate = parseMagicDateTime(dateHeaders[0])
		}
	}

	if len(urlSet) == 0 {
		singleURL := strings.TrimSpace(common.GetNonEmptyLineAfter(body, "permission from our client:"))
		if singleURL != "" {
			urlSet[singleURL] = true
		}
	}

	for urlStr := range urlSet {
		event := events.NewEvent("phishlabscom")
		event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}
		event.EventDate = eventDate
		event.URL = urlStr
		eventsList = append(eventsList, event)
	}

	return eventsList
}

func parseFraudulentUse(serializedEmail *email.SerializedEmail, body string) []*events.Event {
	ip := strings.TrimSpace(common.FindStringWithoutMarkers(body, "IP:", ""))
	urlStr := common.FindStringWithoutMarkers(body, "Fraudulent address:", "")

	var eventDate *time.Time
	if headers := serializedEmail.Headers; headers != nil {
		if dateHeaders := headers["date"]; len(dateHeaders) > 0 {
			eventDate = parseMagicDateTime(dateHeaders[0])
		}
	}

	event := events.NewEvent("phishlabscom")
	event.EventTypes = []events.EventType{events.NewFraud()}
	event.IP = ip
	event.URL = urlStr
	event.EventDate = eventDate

	return []*events.Event{event}
}

func parsePhishlabsMitigation(serializedEmail *email.SerializedEmail, body string) []*events.Event {
	body = strings.ReplaceAll(body, "\"", "'")

	// Extract trademark owner
	ownerRegex := regexp.MustCompile(`(?i)(using|owner of|recently|\('|trademark '|behalf of my client|on behalf of)\s*(.*)\s*(trademarks|became aware|\'\)|\',|\.[\r\n]|\. we)`)
	matches := ownerRegex.FindStringSubmatch(strings.ToLower(body))

	var owner string
	if len(matches) > 2 {
		owner = matches[2]
	} else {
		return nil // Cannot parse owner
	}

	// Extract URL
	var urlStr string
	bodyLower := strings.ToLower(body)

	if strings.Contains(bodyLower, "following url") {
		urlStr = common.GetNonEmptyLineAfter(bodyLower, "following url")
	} else if strings.Contains(bodyLower, "url:") {
		urlStr = strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "url:", ""))
	} else if strings.Contains(bodyLower, "url of concern:") {
		urlStr = strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "url of concern:", ""))
		if !common.IsURL(urlStr) {
			urlStr = strings.TrimSpace(common.GetNonEmptyLineAfter(bodyLower, "url of concern:"))
		}
	} else if strings.Contains(bodyLower, "following website") {
		urlStr = strings.TrimSpace(common.GetNonEmptyLineAfter(bodyLower, "following website"))
	} else if urlRegex := regexp.MustCompile(`(domain at|site at)(\s+)(.*) (which|that)`); urlRegex.MatchString(body) {
		urlMatches := urlRegex.FindStringSubmatch(body)
		if len(urlMatches) > 3 {
			urlStr = urlMatches[3]
		}
	} else if strings.Contains(bodyLower, "below") {
		urlStr = common.GetNonEmptyLineAfter(bodyLower, "below")
	} else {
		return nil // URL couldn't be found
	}

	if !common.IsURL(urlStr) {
		return nil // URL is incorrect
	}

	event := events.NewEvent("phishlabscom")
	trademark := events.NewTrademark("", nil, owner, "")
	event.EventTypes = []events.EventType{trademark}

	if headers := serializedEmail.Headers; headers != nil {
		if dateHeaders := headers["date"]; len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	event.URL = strings.Trim(urlStr, ",.")

	return []*events.Event{event}
}

func getURL(subject string) string {
	protocols := []string{"hxxp", "hxxps", "http", "https"}
	for _, word := range strings.Fields(subject) {
		for _, protocol := range protocols {
			if strings.Contains(word, protocol) {
				return word
			}
		}
	}
	return ""
}

func getTrademarkOwner(body string) string {
	if owner := common.FindStringWithoutMarkers(body, "violation for", "."); owner != "" {
		return strings.TrimSpace(owner)
	}
	if owner := common.FindStringWithoutMarkers(body, "violation of", "federally registered trademark"); owner != "" {
		return strings.TrimSpace(owner)
	}
	return ""
}

func parsePhishlabsTMS(serializedEmail *email.SerializedEmail, body, subject string) []*events.Event {
	body = strings.ToLower(body)
	body = strings.ReplaceAll(body, "</p>", "")
	body = strings.ReplaceAll(body, "<p>", "")

	subject = strings.ToLower(subject)

	event := events.NewEvent("phishlabscom")
	if headers := serializedEmail.Headers; headers != nil {
		if dateHeaders := headers["date"]; len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	var urlStr string
	if u := getURL(subject); u != "" {
		urlStr = u
	} else if urlRegex := regexp.MustCompile(`the url below:\s+(?P<url>\S*)`); urlRegex.MatchString(body) {
		matches := urlRegex.FindStringSubmatch(body)
		if len(matches) > 1 {
			urlStr = matches[1]
		}
	} else if urlRegex := regexp.MustCompile(`(?i)(hosting a site( at)?\s*(?P<url>\S*))`); urlRegex.MatchString(body) {
		matches := urlRegex.FindStringSubmatch(body)
		if len(matches) > 3 {
			urlStr = matches[3]
		}
	} else if urlRegex := regexp.MustCompile(`(?i)(counterfeit goods(.)?\s*(?P<url>\S*))`); urlRegex.MatchString(body) {
		matches := urlRegex.FindStringSubmatch(body)
		if len(matches) > 3 {
			urlStr = matches[3]
		}
	} else if urlRegex := regexp.MustCompile(`by hosting a phishing content:\s+(?P<url>\S*)`); urlRegex.MatchString(body) {
		matches := urlRegex.FindStringSubmatch(body)
		if len(matches) > 1 {
			urlStr = matches[1]
		}
	}

	if urlStr != "" {
		if !strings.Contains(urlStr, "http") {
			urlStr = "http://" + urlStr
		}
		event.URL = strings.ReplaceAll(urlStr, ",", "")

		if strings.Contains(strings.ToLower(body), "trademark") {
			owner := getTrademarkOwner(body)
			trademark := events.NewTrademark("", nil, owner, "")
			event.EventTypes = []events.EventType{trademark}
		} else {
			phishing := events.NewPhishing()
			phishing.PhishingTarget = urlStr
			event.EventTypes = []events.EventType{phishing}
		}

		return []*events.Event{event}
	}

	return nil // No URL found
}

// parseMagicDateTime attempts to parse datetime in various formats
func parseMagicDateTime(dateStr string) *time.Time {
	if dateStr == "" {
		return nil
	}

	dateStr = strings.TrimSpace(dateStr)

	// Common formats to try
	formats := []string{
		time.RFC3339,
		time.RFC1123Z,
		time.RFC1123,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02T15:04:05.999999999",
		"Jan 2 2006 15:04:05",
		"Jan 02 2006 15:04:05",
		"2 Jan 2006 15:04:05",
		"02 Jan 2006 15:04:05",
		"Mon Jan 2 15:04:05 2006",
		"Mon Jan 02 15:04:05 2006",
		"2006-01-02",
		"Mon, 02 Jan 2006 15:04:05 -0700",
		"Mon, 2 Jan 2006 15:04:05 -0700",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return &t
		}
	}

	// Try email.ParseDate for RFC 5322 formats
	if t := email.ParseDate(dateStr); t != nil {
		return t
	}

	return nil
}

// extractDomain extracts a domain from a URL or domain string
func extractDomain(urlStr string) string {
	urlStr = strings.TrimSpace(urlStr)
	if urlStr == "" {
		return ""
	}

	// Clean URL obfuscations
	urlStr = strings.ReplaceAll(urlStr, "hxxp", "http")
	urlStr = strings.ReplaceAll(urlStr, "hXXp", "http")

	// Try to parse as URL
	if !strings.Contains(urlStr, "://") {
		urlStr = "http://" + urlStr
	}

	parsed, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}

	return parsed.Host
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
