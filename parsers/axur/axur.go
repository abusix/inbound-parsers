package axur

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

// stripHTML removes HTML tags from a string (similar to BeautifulSoup text extraction)
func stripHTML(html string) string {
	// Remove script and style tags with their content
	scriptRe := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	html = scriptRe.ReplaceAllString(html, "")
	styleRe := regexp.MustCompile(`(?i)<style[^>]*>.*?</style>`)
	html = styleRe.ReplaceAllString(html, "")

	// Remove all HTML tags
	tagRe := regexp.MustCompile(`<[^>]+>`)
	html = tagRe.ReplaceAllString(html, " ")

	// Normalize whitespace
	wsRe := regexp.MustCompile(`\s+`)
	html = wsRe.ReplaceAllString(html, " ")

	return strings.TrimSpace(html)
}

// parseDMCA parses DMCA report emails
func (p *Parser) parseDMCA(body string, eventTemplate *events.Event) ([]*events.Event, error) {
	var result []*events.Event

	copyrightOwner := ""
	copyrightedWork := ""

	if ownerMatch := regexp.MustCompile(`(?i)copyright (holder|owner): (.+)`).FindStringSubmatch(body); ownerMatch != nil {
		copyrightOwner = strings.TrimSpace(ownerMatch[2])
	}

	if workMatch := regexp.MustCompile(`(?i)material protected by copyright:\s*(\S+)`).FindStringSubmatch(body); workMatch != nil {
		copyrightedWork = workMatch[1]
		if !strings.Contains(copyrightedWork, "http") {
			copyrightedWork = "http://" + strings.ReplaceAll(copyrightedWork, ",", "")
		}
	}

	tag := "Infringing Material:"
	bodyWithTag := strings.Replace(body, tag, tag+"\n", 1)
	urlBlock := common.GetBlockAfterWithStop(bodyWithTag, tag, "")

	for _, url := range urlBlock {
		if common.IsURL(url) {
			event := events.NewEvent(eventTemplate.Parser)
			event.EventDate = eventTemplate.EventDate
			event.EventDetails = eventTemplate.EventDetails
			event.EventTypes = []events.EventType{events.NewCopyright(copyrightedWork, copyrightOwner, "")}
			event.URL = url
			result = append(result, event)
		}
	}

	return result, nil
}

// parseContentRemoval parses content removal emails
func (p *Parser) parseContentRemoval(body string, eventTemplate *events.Event) ([]*events.Event, error) {
	var result []*events.Event

	trademarkOwner := ""
	officialURL := ""

	if ownerMatch := regexp.MustCompile(`(?i)on behalf of (.+?) in issues involving`).FindStringSubmatch(body); ownerMatch != nil {
		trademarkOwner = strings.TrimSpace(ownerMatch[1])
	} else if ownerMatch := regexp.MustCompile(`(?i)of the owner of the brand (\S+) with trademark`).FindStringSubmatch(body); ownerMatch != nil {
		trademarkOwner = ownerMatch[1]
	}

	if officialMatch := regexp.MustCompile(`(?i)(official|legitimate) website( is)?: (http\S+)`).FindStringSubmatch(body); officialMatch != nil {
		officialURL = officialMatch[3]
	}

	for _, tag := range []string{"ATTACHMENT:", "content at your network:"} {
		if strings.Contains(body, tag) {
			bodyWithTag := strings.Replace(body, tag, tag+"\n", 1)
			urlBlock := common.GetBlockAfterWithStop(bodyWithTag, tag, "")
			for _, url := range urlBlock {
				event := events.NewEvent(eventTemplate.Parser)
				event.EventDate = eventTemplate.EventDate
				event.EventDetails = eventTemplate.EventDetails
				trademark := events.NewTrademark("", nil, trademarkOwner, "")
				trademark.OfficialURL = officialURL
				event.EventTypes = []events.EventType{trademark}
				event.URL = url
				result = append(result, event)
			}
			break
		}
	}

	return result, nil
}

// parsePhishing parses phishing emails
func (p *Parser) parsePhishing(body string, eventTemplate *events.Event) ([]*events.Event, error) {
	event := events.NewEvent(eventTemplate.Parser)
	event.EventDate = eventTemplate.EventDate
	event.EventDetails = eventTemplate.EventDetails
	event.EventTypes = []events.EventType{events.NewPhishing()}

	if urlMatch := regexp.MustCompile(`(?i)phishing website hosted at:\s+(http.*)`).FindStringSubmatch(body); urlMatch != nil {
		url := common.CleanURL(urlMatch[1])
		url = strings.ReplaceAll(url, "[://]", "")
		event.URL = url
	}

	if ipMatch := regexp.MustCompile(`(?i)ip:\s*(\d.*)`).FindStringSubmatch(body); ipMatch != nil {
		ip := strings.ReplaceAll(ipMatch[1], " ", "")
		ip = strings.ReplaceAll(ip, "[.]", ".")
		event.IP = ip
	}

	return []*events.Event{event}, nil
}

// parseScamWebsite parses scam website emails
func (p *Parser) parseScamWebsite(body string, eventTemplate *events.Event) ([]*events.Event, error) {
	event := events.NewEvent(eventTemplate.Parser)
	event.EventDate = eventTemplate.EventDate
	event.EventDetails = eventTemplate.EventDetails
	event.EventTypes = []events.EventType{events.NewFraud()}

	if urlMatch := regexp.MustCompile(`(?i)a scam website hosted at your network:\s*(http\S+)`).FindStringSubmatch(body); urlMatch != nil {
		event.URL = urlMatch[1]
	} else {
		urlCandidate := common.GetNonEmptyLineAfter(body, "Fake auction website")
		if common.IsURL(urlCandidate) {
			event.URL = urlCandidate
		}
	}

	if ipMatch := regexp.MustCompile(`(?i)ip:\s*(\S+)`).FindStringSubmatch(body); ipMatch != nil {
		event.IP = ipMatch[1]
	}

	return []*events.Event{event}, nil
}

// parsePharming parses pharming emails
func (p *Parser) parsePharming(body string, eventTemplate *events.Event) ([]*events.Event, error) {
	event := events.NewEvent(eventTemplate.Parser)
	event.EventDate = eventTemplate.EventDate
	event.EventDetails = eventTemplate.EventDetails
	event.EventTypes = []events.EventType{events.NewRogueDNS()}

	if ipMatch := regexp.MustCompile(`(?i)dns server ip address:\s*(\S+)`).FindStringSubmatch(body); ipMatch != nil {
		event.IP = ipMatch[1]
		return []*events.Event{event}, nil
	}

	return nil, nil
}

// parseMalicious parses malicious artifact emails
func (p *Parser) parseMalicious(body string, eventTemplate *events.Event) ([]*events.Event, error) {
	event := events.NewEvent(eventTemplate.Parser)
	event.EventDate = eventTemplate.EventDate
	event.EventDetails = eventTemplate.EventDetails
	event.EventTypes = []events.EventType{events.NewMaliciousActivity()}

	if urlMatch := regexp.MustCompile(`(?i)the artifact is hosted at:\s*(\S+)`).FindStringSubmatch(body); urlMatch != nil {
		event.URL = urlMatch[1]
	}

	if ip := common.FindStringWithoutMarkers(strings.ToLower(body), "ip:", ""); ip != "" {
		event.IP = ip
	}

	if event.IP != "" || event.URL != "" {
		return []*events.Event{event}, nil
	}

	return nil, nil
}

// parseCopyright parses copyright emails (false promise variant)
func (p *Parser) parseCopyright(body string, eventTemplate *events.Event) ([]*events.Event, error) {
	copyrightOwner := ""
	copyrightedWork := ""

	if ownerMatch := regexp.MustCompile(`(?i)copyright (holder|owner): (.+)`).FindStringSubmatch(body); ownerMatch != nil {
		copyrightOwner = strings.TrimSpace(ownerMatch[2])
	}

	if workMatch := regexp.MustCompile(`(?i)material protected by copyright:\s*(\S+)`).FindStringSubmatch(body); workMatch != nil {
		copyrightedWork = workMatch[1]
		if !strings.Contains(copyrightedWork, "http") {
			copyrightedWork = "http://" + strings.ReplaceAll(copyrightedWork, ",", "")
		}
	}

	event := events.NewEvent(eventTemplate.Parser)
	event.EventDate = eventTemplate.EventDate
	event.EventDetails = eventTemplate.EventDetails
	event.EventTypes = []events.EventType{events.NewCopyright(copyrightedWork, copyrightOwner, "")}

	if infringingURL := regexp.MustCompile(`(?i)The following site promotes illegally.*\s*(http\S+)`).FindStringSubmatch(body); infringingURL != nil {
		event.URL = infringingURL[1]
		return []*events.Event{event}, nil
	}

	return nil, common.NewParserError("Couldn't find infringing URL")
}

// parseFakeProfile parses fake profile emails
func (p *Parser) parseFakeProfile(body string, eventTemplate *events.Event) ([]*events.Event, error) {
	event := events.NewEvent(eventTemplate.Parser)
	event.EventDate = eventTemplate.EventDate
	event.EventDetails = eventTemplate.EventDetails

	officialURL := strings.TrimSpace(common.FindStringWithoutMarkers(strings.ToLower(body), "official website:", ""))
	regNumber := common.FindStringWithoutMarkers(strings.ToLower(body), "registration number ", ".")

	var regNumbers []string
	if regNumber != "" {
		regNumbers = []string{regNumber}
	}

	trademark := events.NewTrademark("", regNumbers, "", "")
	trademark.OfficialURL = officialURL
	event.EventTypes = []events.EventType{trademark}
	event.URL = common.GetNonEmptyLineAfter(body, "ATTACHMENT")

	return []*events.Event{event}, nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Strip HTML to get plain text (similar to BeautifulSoup)
	body = stripHTML(body)

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	eventTemplate := events.NewEvent("axur")

	// Extract event date from headers
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			// Store as string for now - date parsing can be added later if needed
			// eventTemplate.EventDate = parseDate(dateHeaders[0])
		}
	}

	// Extract external ID from subject
	if idMatch := regexp.MustCompile(`Tracking: #(\S+)\)`).FindStringSubmatch(subject); idMatch != nil {
		externalID := idMatch[1]
		eventTemplate.AddEventDetail(&events.ExternalID{ID: externalID})
	}

	subjectLower := strings.ToLower(subject)

	// Route to appropriate parser based on subject
	cleanedSubject := strings.ReplaceAll(subjectLower, "takedown ", "")
	if strings.Contains(cleanedSubject, "dmca report") || strings.Contains(cleanedSubject, "dmca notice") {
		return p.parseDMCA(body, eventTemplate)
	} else if strings.Contains(subjectLower, "content removal") {
		return p.parseContentRemoval(body, eventTemplate)
	} else if strings.Contains(subjectLower, "phishing hosted at") {
		return p.parsePhishing(body, eventTemplate)
	} else if strings.Contains(subjectLower, "scam website") || strings.Contains(subjectLower, "scam report") || strings.Contains(subjectLower, "fake auction removal") {
		return p.parseScamWebsite(body, eventTemplate)
	} else if strings.Contains(subjectLower, "abuse report - pharming") {
		return p.parsePharming(body, eventTemplate)
	} else if strings.Contains(subjectLower, "malicious artifact hosted") {
		return p.parseMalicious(body, eventTemplate)
	} else if strings.Contains(subjectLower, "false promise") && strings.Contains(strings.ToLower(body), "copyright") {
		return p.parseCopyright(body, eventTemplate)
	} else if strings.Contains(subjectLower, "fake profile") {
		return p.parseFakeProfile(body, eventTemplate)
	}

	return nil, fmt.Errorf("unknown email type: %s", subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
