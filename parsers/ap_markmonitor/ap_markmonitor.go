package ap_markmonitor

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	urlPattern  = regexp.MustCompile(`(?i)(your ref:|your website,)[^h.]*([^\s]+)`)
	urlPattern2 = regexp.MustCompile(`(?i)(hosted on the site)[^h.]*([^\s]+)`)
)

func NewParser() *Parser {
	return &Parser{}
}

func getExternalID(lines []string) string {
	for _, line := range lines {
		if strings.Contains(line, "caseid-") {
			extracted := common.FindStringWithoutMarkers(line, "caseid-", "")
			parts := strings.Fields(extracted)
			if len(parts) > 0 {
				return strings.ReplaceAll(parts[0], "-", "")
			}
		}
	}
	return ""
}

func cleanDate(line string) string {
	if strings.Contains(strings.ToLower(line), "monitored at") {
		return strings.ReplaceAll(line, " - ", " ")
	}
	return line
}

func parseCopyright(date, subject, body string) ([]*events.Event, error) {
	var results []*events.Event
	eventTemplate := events.NewEvent("ap_markmonitor")
	eventTemplate.EventDate = email.ParseDate(date)
	eventTemplate.IP = subject

	copyrightOwner := ""
	copyrightedWork := ""

	// Extract copyright owner
	owners := common.FindStringWithoutMarkers(body, "on behalf of MarkMonitors client,", `("Owners")`)
	owners = strings.ReplaceAll(owners, "\r\n", "")
	owners = strings.ReplaceAll(owners, "\n", "")
	if owners != "" {
		copyrightOwner = owners
	}

	// Extract copyrighted work
	for _, tag := range []string{"Identification of copyrighted work(s):", "Identification of copyrighted work:"} {
		if strings.Contains(body, tag) {
			bodyModified := strings.ReplaceAll(body, tag, tag+"\n\n")
			copyrightedWorkBlock := common.GetBlockAfterWithStop(bodyModified, tag, "")
			if len(copyrightedWorkBlock) > 0 {
				copyrightedWork = strings.Join(copyrightedWorkBlock, "; ")
			}
			break
		}
	}

	// Extract URLs
	foundURL := false
	for _, tag := range []string{
		"material or activity found at the following location(s):",
		"infringement by your customer:",
		"sample of infringement by your customer:",
	} {
		if strings.Contains(body, tag) {
			foundURL = true
			bodyModified := strings.ReplaceAll(body, tag, tag+"\n\n")
			urlsBlock := common.GetBlockAfterWithStop(bodyModified, tag, "")
			for _, urlLine := range urlsBlock {
				event := *eventTemplate
				event.EventTypes = []events.EventType{events.NewCopyright(copyrightedWork, copyrightOwner, "")}
				parts := strings.Fields(urlLine)
				if len(parts) > 0 {
					event.URL = strings.TrimSpace(parts[0])
				}
				results = append(results, &event)
			}
			break
		}
	}

	if !foundURL {
		return nil, common.NewParserError("no url found")
	}

	return results, nil
}

func parseSimpleCopyright(serializedEmail *email.SerializedEmail, body, subjectLower string, useUtilFunction bool) ([]*events.Event, error) {
	event := events.NewEvent("ap_markmonitor")

	var dateFallback string
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		dateFallback = dateHeader[0]
	}

	if useUtilFunction {
		if externalID := getExternalID([]string{subjectLower + "\n"}); externalID != "" {
			event.AddEventDetail(&events.ExternalID{ID: externalID})
		}

		if !strings.Contains(body, "details are:") {
			url := common.FindStringWithoutMarkers(body, "disseminated on the website", "is being displayed")
			event.URL = strings.TrimSpace(url)

			if event.URL == "" {
				eligibleURL := common.GetNonEmptyLineAfter(body, "location(s):")
				event.URL = strings.TrimSpace(eligibleURL)
			}

			event.EventDate = email.ParseDate(dateFallback)

			copyrightOwner := common.FindStringWithoutMarkers(body, "controlled by", "and/or its affiliates")
			copyrightOwner = strings.TrimSpace(copyrightOwner)
			if copyrightOwner == "" {
				copyrightOwner = common.FindStringWithoutMarkers(body, "I write on behalf of", ".")
				copyrightOwner = strings.TrimSpace(copyrightOwner)
			}

			event.EventTypes = []events.EventType{events.NewCopyright("", copyrightOwner, "")}
		} else {
			// Handle details block
			detailsBlock := common.GetBlockAfterWithStop(body, "details are:", "")
			var cleanedLines []string
			for _, line := range detailsBlock {
				cleanedLines = append(cleanedLines, cleanDate(line))
			}
			detailsStr := strings.Join(cleanedLines, "\n")

			// Use basic copyright parser logic (simplified version)
			event.EventDate = email.ParseDate(dateFallback)
			event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}

			// Try to extract URL from details
			for _, line := range cleanedLines {
				if strings.Contains(strings.ToLower(line), "http") {
					event.URL = strings.TrimSpace(line)
					break
				}
			}
			_ = detailsStr
		}
	} else {
		event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}
		event.EventDate = email.ParseDate(common.FindStringWithoutMarkers(body, "at:", ""))
		event.IP = common.FindStringWithoutMarkers(body, "ip:", "")
		event.URL = common.FindStringWithoutMarkers(body, "url:", "")

		if externalID := getExternalID([]string{body}); externalID != "" {
			event.AddEventDetail(&events.ExternalID{ID: externalID})
		}
	}

	return []*events.Event{event}, nil
}

func parseTrademark(body string, serializedEmail *email.SerializedEmail, subjectLower string) ([]*events.Event, error) {
	event := events.NewEvent("ap_markmonitor")

	var dateFallback string
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		dateFallback = dateHeader[0]
	}
	event.EventDate = email.ParseDate(dateFallback)

	match := urlPattern.FindStringSubmatch(body)
	if len(match) > 2 {
		event.URL = match[2]
	}

	markers := []string{"Globo International Company Ltd"}
	trademarkOwner := ""
	officialURL := ""
	for _, marker := range markers {
		if strings.Contains(body, marker) {
			trademarkOwner = marker
			officialURL = common.FindStringWithoutMarkers(body, "Globo News G1 ", " ")
			break
		}
	}

	if event.URL != "" {
		event.EventTypes = []events.EventType{events.NewTrademark("", nil, trademarkOwner, officialURL)}
		if externalID := getExternalID([]string{subjectLower + "\n"}); externalID != "" {
			event.AddEventDetail(&events.ExternalID{ID: externalID})
		}
		return []*events.Event{event}, nil
	}

	return nil, common.NewParserError("no url found")
}

func getURL(body string) string {
	startMarker := "its contents from view."
	if strings.Contains(body, startMarker) {
		startIndex := strings.Index(strings.ToLower(body), strings.ToLower(startMarker)) + len(startMarker)
		endIndex := strings.Index(strings.ToLower(body), "i hereby state that")

		if endIndex == -1 {
			endIndex = len(body)
		}

		urlBlockLines := []string{}
		for _, line := range strings.Split(body[startIndex:endIndex], "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && trimmed != "\n" && trimmed != "\r" {
				urlBlockLines = append(urlBlockLines, trimmed)
			}
		}

		for _, line := range urlBlockLines {
			if strings.HasPrefix(line, "http") {
				return common.CleanURL(line)
			}
		}
	} else {
		match := urlPattern.FindStringSubmatch(body)
		if len(match) > 2 {
			url := strings.ReplaceAll(match[2], ",", "")
			return url
		}
	}

	if match := urlPattern2.FindStringSubmatch(body); len(match) > 2 {
		return common.CleanURL(match[2])
	}

	return ""
}

func parseNbaNflNhl(body string, serializedEmail *email.SerializedEmail, fromAddr, subjectLower string) ([]*events.Event, error) {
	event := events.NewEvent("ap_markmonitor")

	var dateFallback string
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		dateFallback = dateHeader[0]
	}
	event.EventDate = email.ParseDate(dateFallback)

	event.URL = getURL(body)

	if event.URL != "" {
		copyrightOwner := ""
		if strings.Contains(fromAddr, "nfl") {
			copyrightOwner = "NFL Productions LLC"
		} else if strings.Contains(fromAddr, "nba") {
			copyrightOwner = "National Basketball Association and/or NBA Properties, Inc"
		} else if strings.Contains(fromAddr, "nhl") {
			copyrightOwner = "NHL Enterprises, L.P"
		}

		event.EventTypes = []events.EventType{events.NewCopyright("", copyrightOwner, "")}
		if externalID := getExternalID([]string{subjectLower + "\n", strings.ToLower(body) + "\n"}); externalID != "" {
			event.AddEventDetail(&events.ExternalID{ID: externalID})
		}
		return []*events.Event{event}, nil
	}

	return nil, common.NewParserError("no url found")
}

func parseChineseInfringement(body, date, subject string) ([]*events.Event, error) {
	event := events.NewEvent("ap_markmonitor")
	owner := common.FindStringWithoutMarkers(subject, "侵权", "事宜")
	owner = strings.TrimSpace(owner)
	event.EventDate = email.ParseDate(date)

	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, "您的网站") && strings.Contains(line, "http") {
			event.URL = line
			break
		}
	}

	if event.URL == "" {
		return nil, common.NewParserError("Failed to extract url!")
	}

	event.EventTypes = []events.EventType{events.NewCopyright("", owner, "")}
	if externalID := getExternalID([]string{strings.ToLower(subject) + "\n", strings.ToLower(body) + "\n"}); externalID != "" {
		event.AddEventDetail(&events.ExternalID{ID: externalID})
	}
	return []*events.Event{event}, nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	var dateFallback string
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		dateFallback = dateHeader[0]
	}

	// Get from address
	fromAddr := ""
	if from, ok := serializedEmail.Headers["from"]; ok && len(from) > 0 {
		fromAddr = strings.ToLower(from[0])
	}

	if strings.Contains(subjectLower, "notice of claimed infringement") {
		return parseCopyright(dateFallback, subjectLower, body)
	} else if strings.Contains(subjectLower, "infringement") && strings.Contains(strings.ToLower(body), "url:") {
		return parseSimpleCopyright(serializedEmail, strings.ToLower(body), subjectLower, false)
	} else if strings.Contains(subjectLower, "infringement") {
		if strings.Contains(subjectLower, "trademark") || strings.Contains(strings.ToLower(body), "trademark") {
			return parseTrademark(body, serializedEmail, subjectLower)
		} else if strings.Contains(fromAddr, "nba") || strings.Contains(fromAddr, "nfl") || strings.Contains(fromAddr, "nhl") {
			return parseNbaNflNhl(body, serializedEmail, fromAddr, subjectLower)
		} else {
			return parseSimpleCopyright(serializedEmail, strings.ToLower(body), subjectLower, true)
		}
	} else if strings.Contains(subject, "侵权") {
		return parseChineseInfringement(body, dateFallback, subject)
	}

	return nil, common.NewParserError("unknown email type: " + subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
