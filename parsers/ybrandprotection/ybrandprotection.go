package ybrandprotection

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	htmlTagPattern = regexp.MustCompile(`<[^>]+>`)
)

func NewParser() *Parser {
	return &Parser{}
}

// removeHTML removes HTML tags from a string
func removeHTML(s string) string {
	return htmlTagPattern.ReplaceAllString(s, "")
}

// getURLBlock extracts the URL block from the body
func getURLBlock(body string) string {
	urlBlock := common.FindStringWithoutMarkers(body, "following listings", "Kind Regards")
	urlBlock = strings.TrimSpace(urlBlock)
	if urlBlock == "" {
		urlBlock = common.FindStringWithoutMarkers(body, "following link(s)", "I have a good faith belief")
		urlBlock = strings.TrimSpace(urlBlock)
	}
	return urlBlock
}

// parseDrSeuss handles emails from dr.seuss@ybrandprotection.com
func parseDrSeuss(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Determine event type based on subject
	var eventType events.EventType
	matched, _ := regexp.MatchString(`(?i)notice of (ipr )?infringement`, subject)
	if matched {
		eventType = &events.Trademark{
			BaseEventType: events.BaseEventType{
				Name: "trademark",
				Type: "trademark",
			},
			TrademarkOwner: "Dr. Seuss Enterprises, L.P.",
		}
	} else {
		return nil, common.NewNewTypeError(subject)
	}

	// Get date from headers
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	// Extract URLs
	urlBlock := getURLBlock(body)
	lines := strings.Split(urlBlock, "\n")

	var results []*events.Event
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if common.IsURL(line) {
			event := events.NewEvent("ybrandprotection")
			event.EventDate = eventDate
			event.EventTypes = []events.EventType{eventType}
			event.URL = line
			results = append(results, event)
		}
	}

	if len(results) == 0 {
		return nil, common.NewParserError("no URLs found")
	}

	return results, nil
}

// parseDesio handles emails from desio.ipr@ybrandprotection.com
func parseDesio(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	bodyLower := strings.ToLower(body)

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	var eventType events.EventType
	if strings.Contains(subjectLower, "copyright infringement") {
		officialURL := common.FindStringWithoutMarkers(bodyLower, "official website", ".\n")
		eventType = &events.Copyright{
			BaseEventType: events.BaseEventType{
				Name: "copyright",
				Type: "copyright",
			},
			CopyrightOwner: "Desio Srl.",
			OfficialURL:    officialURL,
		}
	} else {
		return nil, common.NewNewTypeError(subject)
	}

	// Get date from headers
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	// Extract URLs - get block after marker and continue until end
	urlBlock := common.GetBlockAfterWithStop(bodyLower, "take down the infringing webpage", "")

	var results []*events.Event
	for _, line := range urlBlock {
		line = strings.TrimSpace(line)
		if common.IsURL(line) {
			event := events.NewEvent("ybrandprotection")
			event.EventDate = eventDate
			event.EventTypes = []events.EventType{eventType}
			event.URL = removeHTML(line)
			results = append(results, event)
		}
	}

	if len(results) == 0 {
		return nil, common.NewParserError("no URLs found")
	}

	return results, nil
}

// parseRenaultIPR handles emails from renault.ipr@ybrandprotection.com
func parseRenaultIPR(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Get date from headers
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	event := events.NewEvent("ybrandprotection")
	event.EventDate = eventDate
	event.EventTypes = []events.EventType{
		&events.Trademark{
			BaseEventType: events.BaseEventType{
				Name: "trademark",
				Type: "trademark",
			},
			TrademarkOwner: "Renault",
		},
	}

	url := common.FindStringWithoutMarkers(body, "published in correspondence of the domain name", ",")
	event.URL = strings.TrimSpace(url)

	return []*events.Event{event}, nil
}

// parsePhishingAndTrademark handles phishing and trademark abuse notices
func parsePhishingAndTrademark(serializedEmail *email.SerializedEmail, subjectLower string) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	bodyLower := strings.ToLower(body)

	// Get date from headers
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	// Extract official URL
	urlStartPattern := regexp.MustCompile(`(?P<official_website>(?!phishing\b)\b\S+ (website|website login):)`)
	urlStartMatch := urlStartPattern.FindStringSubmatch(bodyLower)
	if len(urlStartMatch) < 2 {
		return nil, common.NewNewTypeError(subjectLower)
	}

	officialStart := urlStartMatch[1]
	officialURL := common.GetNonEmptyLineAfter(bodyLower, officialStart)
	officialURL = strings.TrimSpace(officialURL)

	var eventType events.EventType
	if common.IsURL(officialURL) {
		eventType = events.NewPhishingWithOfficialURL(officialURL)
	} else {
		return nil, common.NewNewTypeError(subjectLower)
	}

	// Extract IP address
	ip := common.ExtractOneIP(subjectLower)
	if ip == "" {
		line := common.FindStringWithoutMarkers(bodyLower, "phishing and trademark abuse notice", "\n")
		ip = common.ExtractOneIP(line)
	}

	// Extract phishing websites
	phishingWebsites := common.FindStringWithoutMarkers(bodyLower, "phishing website:", officialStart)
	lines := strings.Split(phishingWebsites, "\n")

	var results []*events.Event
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if common.IsURL(line) {
			event := events.NewEvent("ybrandprotection")
			event.EventDate = eventDate
			event.EventTypes = []events.EventType{eventType}
			event.IP = ip
			event.URL = line
			results = append(results, event)
		}
	}

	if len(results) == 0 {
		return nil, common.NewParserError("no phishing URLs found")
	}

	return results, nil
}

// parseTrademarkInfringementPayPal handles trademark infringement notices from paypal.ipr
func parseTrademarkInfringementPayPal(serializedEmail *email.SerializedEmail, subjectLower string) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	bodyLower := strings.ToLower(body)

	event := events.NewEvent("ybrandprotection")

	// Get date from headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		event.EventDate = email.ParseDate(dateHeader[0])
	}

	// Extract trademarked material
	bodyModified := strings.ReplaceAll(bodyLower, ", among others", ".")
	trademarkedMaterial := common.FindStringWithoutMarkers(bodyModified, ", such as the", ".")
	trademarkedMaterial = strings.TrimSpace(trademarkedMaterial)

	event.EventTypes = []events.EventType{
		&events.Trademark{
			BaseEventType: events.BaseEventType{
				Name: "trademark",
				Type: "trademark",
			},
			TrademarkOwner:      "paypal, inc.",
			TrademarkedMaterial: trademarkedMaterial,
		},
	}

	// Extract IP address
	ipLine := common.FindStringWithoutMarkers(bodyLower, "ip address", ",")
	ip := common.ExtractOneIP(ipLine)
	event.IP = ip

	// Extract URL
	urlLine := common.FindStringWithoutMarkers(bodyLower, "the infringements are located at:", "you")
	urlLine = strings.TrimSpace(urlLine)
	if common.IsURL(urlLine) {
		event.URL = urlLine
	}

	return []*events.Event{event}, nil
}

// parseBobcat handles emails from bobcat.ipr@ybrandprotection.com
func parseBobcat(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Try to get HTML body first
	htmlBody, _ := common.FindFirstAttachmentWithMimeType(serializedEmail, "html")
	var body string
	if htmlBody != "" {
		htmlBody = strings.ReplaceAll(htmlBody, "\r\n", "\n")
		// Simple HTML to text conversion - replace <br> with newlines
		htmlBody = regexp.MustCompile(`<br\s*/?>|<br\s*>`).ReplaceAllString(htmlBody, "\n")
		body = htmlTagPattern.ReplaceAllString(htmlBody, "")
		body = strings.ToLower(body)
	} else {
		var err error
		body, err = common.GetBody(serializedEmail, true)
		if err != nil {
			return nil, err
		}
		body = strings.ToLower(body)
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	// Get date from headers
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	var eventType events.EventType
	var urlStartMarker string

	if strings.Contains(subjectLower, "unauthorized use of bobcat trademarks") {
		eventType = &events.Trademark{
			BaseEventType: events.BaseEventType{
				Name: "trademark",
				Type: "trademark",
			},
			TrademarkOwner: "Bobcat Company",
		}
		urlStartMarker = "the infringements are located at:"
	} else if strings.Contains(subjectLower, "dmca notice") {
		officialURL := common.FindStringWithoutMarkers(body, "originally found on their website at", ".\n")
		officialURL = strings.ReplaceAll(officialURL, "&nbsp;", "")
		eventType = &events.Copyright{
			BaseEventType: events.BaseEventType{
				Name: "copyright",
				Type: "copyright",
			},
			CopyrightOwner: "Bobcat Company",
			OfficialURL:    officialURL,
		}
		urlStartMarker = "copyrighted images located at:"
	} else {
		return nil, common.NewNewTypeError(subject)
	}

	// Get block around URL marker - continue until end
	urlBlock, _ := common.GetBlockAroundWithContinueUntil(body, urlStartMarker, "")

	var results []*events.Event
	found := false
	for _, line := range urlBlock {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		event := events.NewEvent("ybrandprotection")
		event.EventDate = eventDate
		event.EventTypes = []events.EventType{eventType}

		// Try to set URL - if it fails, check if we've found any URLs yet
		if !common.IsURL(line) {
			if found {
				// Assume the URL block is done
				break
			}
			continue
		}

		event.URL = line
		event.IP = common.ExtractOneIP(subject) // Extract IP from subject
		found = true
		results = append(results, event)
	}

	if len(results) == 0 {
		return nil, common.NewParserError("no URLs found")
	}

	return results, nil
}

// parseLundbeckIPR handles emails from lundbeck.ipr@ybrandprotection.com
func parseLundbeckIPR(serializedEmail *email.SerializedEmail, subjectLower string) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	bodyLower := strings.ToLower(body)

	// Parse date from subject if present
	var eventDate *time.Time
	datePattern := regexp.MustCompile(`\d{2}\w{3}\d{4}`)
	dateMatch := datePattern.FindString(subjectLower)
	if dateMatch != "" {
		parsedTime, err := time.Parse("02Jan2006", dateMatch)
		if err == nil {
			eventDate = &parsedTime
		}
	}

	// Fallback to header date
	if eventDate == nil {
		if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
			eventDate = email.ParseDate(dateHeader[0])
		}
	}

	eventType := &events.Trademark{
		BaseEventType: events.BaseEventType{
			Name: "trademark",
			Type: "trademark",
		},
		TrademarkOwner: "h. lundbeck a/s",
	}

	// Extract URLs from body
	bodyModified := strings.ReplaceAll(bodyLower, "a conduct", "conduct")
	urlBlock := common.FindStringWithoutMarkers(bodyModified, "www.lundbeck.com.", "such conduct")
	lines := strings.Split(urlBlock, "\n")

	var urls []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if common.IsURL(line) {
			urls = append(urls, line)
		}
	}

	var results []*events.Event
	if len(urls) > 0 {
		for _, url := range urls {
			event := events.NewEvent("ybrandprotection")
			event.EventDate = eventDate
			event.EventTypes = []events.EventType{eventType}
			event.URL = url
			results = append(results, event)
		}
	} else {
		// Try to extract URL from subject
		urlPattern := regexp.MustCompile(`\d{2}\w{3}\d{4}\s+-\s+(?P<url>\S+)`)
		urlMatch := urlPattern.FindStringSubmatch(subjectLower)
		if len(urlMatch) > 1 {
			event := events.NewEvent("ybrandprotection")
			event.EventDate = eventDate
			event.EventTypes = []events.EventType{eventType}
			event.URL = urlMatch[1]
			results = append(results, event)
		}
	}

	if len(results) == 0 {
		return nil, common.NewParserError("no URLs found")
	}

	return results, nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	fromAddr, err := common.GetFrom(serializedEmail, false)
	if err != nil || fromAddr == "" {
		return nil, common.NewParserError("no from address")
	}
	fromAddr = strings.ToLower(fromAddr)

	// Check for auto-replies and re: subjects for certain senders
	if fromAddr == "dr.seuss@ybrandprotection.com" || fromAddr == "lundbeck.ipr@ybrandprotection.com" {
		if strings.HasPrefix(subjectLower, "automatic reply") {
			return nil, common.NewRejectError("automatic reply")
		}
		if strings.HasPrefix(subjectLower, "re:") {
			return nil, common.NewRejectError("reply email")
		}
	}

	// Route to appropriate parser based on from address
	switch fromAddr {
	case "dr.seuss@ybrandprotection.com":
		return parseDrSeuss(serializedEmail)

	case "desio.ipr@ybrandprotection.com":
		return parseDesio(serializedEmail)

	case "renault.ipr@ybrandprotection.com":
		return parseRenaultIPR(serializedEmail)

	case "bobcat.ipr@ybrandprotection.com":
		return parseBobcat(serializedEmail)

	case "paypal.ipr@ybrandprotection.com":
		if strings.Contains(subjectLower, "trademark infringement notice") ||
			strings.Contains(subjectLower, "notice of infringement") {
			return parseTrademarkInfringementPayPal(serializedEmail, subjectLower)
		}
		if strings.Contains(subjectLower, "phishing and trademark abuse notice") {
			return parsePhishingAndTrademark(serializedEmail, subjectLower)
		}
		return nil, common.NewNewTypeError(subject)

	case "lundbeck.ipr@ybrandprotection.com":
		return parseLundbeckIPR(serializedEmail, subjectLower)

	default:
		return nil, fmt.Errorf("unknown from address: %s", fromAddr)
	}
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
