package friendmts

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var courtOrderPattern = regexp.MustCompile(`(?i)(http.*fmtsoperations\.com/.+\.(?:pdf|PDF))`)

func NewParser() *Parser {
	return &Parser{}
}

// getLinebreak returns the line break character used in text
func getLinebreak(text string) string {
	if strings.Contains(text, "\r\n") {
		return "\r\n"
	}
	return "\n"
}

// parseEscalatedCopyrightInfringement handles escalated copyright reports
func (p *Parser) parseEscalatedCopyrightInfringement(serializedEmail *email.SerializedEmail, subject, body, fromAddr string) ([]*events.Event, error) {
	event := events.NewEvent("friendmts")

	bodyLower := strings.ToLower(body)
	endMarker := getLinebreak(body)

	// Try to extract IP from subject first, otherwise from body
	if ipAddr := common.ExtractOneIP(subject); ipAddr != "" {
		event.IP = ipAddr
	} else {
		event.IP = common.FindStringWithoutMarkers(bodyLower, "ip address:", endMarker)
	}

	// Parse event date
	var eventDate *time.Time
	dateSeen := common.FindStringWithoutMarkers(body, "Date seen", endMarker)
	if strings.Contains(dateSeen, "During the live broadcast") {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventDate = email.ParseDate(dateHeaders[0])
		}
	} else if dateSeen != "" {
		eventDate = email.ParseDate(dateSeen)
	}

	// Try alternative date formats
	if eventDate == nil && strings.Contains(bodyLower, "observed at:") {
		dateStr := common.FindStringWithoutMarkers(bodyLower, "observed at:", endMarker)
		eventDate = email.ParseDate(dateStr)
	}

	if eventDate == nil && strings.Contains(bodyLower, "timestamp seen:") {
		dateStr := common.FindStringWithoutMarkers(bodyLower, "timestamp seen:", "<br>")
		dateStr = strings.Trim(dateStr, " *")
		dateStr = strings.ReplaceAll(dateStr, "/", "-")
		if parsed := email.ParseDate(dateStr); parsed != nil {
			eventDate = parsed
		} else {
			// Try adding seconds
			if parsed := email.ParseDate(dateStr + ":00"); parsed != nil {
				eventDate = parsed
			} else {
				return nil, common.NewParserError("date was not parsed: " + dateStr)
			}
		}
	}

	if eventDate == nil && strings.Contains(bodyLower, "timestamp (utc):") {
		dateStr := common.FindStringWithoutMarkers(bodyLower, "timestamp (utc):", endMarker)
		if strings.Contains(dateStr, "<br>") {
			dateStr = strings.Split(dateStr, "<br>")[0]
		}
		if !strings.Contains(strings.ToLower(dateStr), "during the live broadcast") {
			eventDate = email.ParseDate(dateStr)
		}
	}

	// Fall back to email date header
	if eventDate == nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventDate = email.ParseDate(dateHeaders[0])
		}
	}
	event.EventDate = eventDate

	// Extract URLs
	tcURL := common.FindStringWithoutMarkers(body, "tcUrl:", endMarker)
	if tcURL != "" {
		evidence := &events.Evidence{}
		evidence.AddEvidence(events.UrlStore{
			Description: "tc",
			URL:         strings.TrimSpace(tcURL),
		})
		event.AddEventDetail(evidence)
	}

	swfURL := common.FindStringWithoutMarkers(body, "swfUrl:", endMarker)
	if swfURL != "" {
		evidence := &events.Evidence{}
		evidence.AddEvidence(events.UrlStore{
			Description: "swf",
			URL:         strings.TrimSpace(swfURL),
		})
		event.AddEventDetail(evidence)
	}

	pageURL := strings.TrimSpace(common.FindStringWithoutMarkers(body, "pageUrl:", endMarker))
	if pageURL == "" {
		pageURL = strings.Trim(common.FindStringWithoutMarkers(body, "URL:", endMarker), "\n\t *")
	}
	event.URL = pageURL

	// Extract incident ID
	externalID := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Incident ID:", endMarker))
	if strings.Contains(externalID, "<br>") {
		externalID = strings.TrimSpace(common.FindStringWithoutMarkers(body, "Incident ID:", "<br>"))
	}
	if externalID != "" {
		event.AddEventDetail(&events.ExternalID{ID: externalID})
	}

	// Extract content owner
	owner := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Content Owner:", endMarker))
	event.SenderEmail = fromAddr
	event.EventTypes = []events.EventType{events.NewCopyright("", owner, "")}

	return []*events.Event{event}, nil
}

// parseCopyrightInfringement handles simple copyright infringement reports
func (p *Parser) parseCopyrightInfringement(serializedEmail *email.SerializedEmail, subject, body, fromAddr string) ([]*events.Event, error) {
	event := events.NewEvent("friendmts")

	event.IP = common.ExtractOneIP(subject)

	// Set event date from email date
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Extract blocked until date
	dateBlockedUntil := common.FindString(body, "Periods Until: ", "\n")
	if dateBlockedUntil != "" {
		parts := strings.Split(dateBlockedUntil, ":")
		if len(parts) > 1 {
			blocked := strings.Trim(parts[1], " []")
			event.AddEventDetailSimple("blocked_until", blocked)
		}
	}

	// Extract court order URL
	if match := courtOrderPattern.FindStringSubmatch(body); len(match) > 1 {
		evidence := &events.Evidence{}
		evidence.AddEvidence(events.UrlStore{
			Description: "court",
			URL:         match[1],
		})
		event.AddEventDetail(evidence)
	}

	event.SenderEmail = fromAddr
	event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}

	return []*events.Event{event}, nil
}

// parseSimpleCopyright handles simple copyright reports with URL and IP lists
func (p *Parser) parseSimpleCopyright(serializedEmail *email.SerializedEmail, body, urlStartMarker, urlEndMarker, ipStartMarker, ipEndMarker string) ([]*events.Event, error) {
	bodyLower := strings.ToLower(body)

	urlBlock := common.FindStringWithoutMarkers(bodyLower, urlStartMarker, urlEndMarker)
	ipBlock := common.FindStringWithoutMarkers(bodyLower, ipStartMarker, ipEndMarker)

	// Extract URLs
	urlPattern := regexp.MustCompile(`http\S+`)
	urlMatches := urlPattern.FindAllString(urlBlock, -1)
	urls := make(map[string]bool)
	for _, url := range urlMatches {
		urls[url] = true
	}

	// Extract IPs
	ipPattern := regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	ipMatches := ipPattern.FindAllString(ipBlock, -1)
	ips := make(map[string]bool)
	for _, ip := range ipMatches {
		ips[ip] = true
	}

	var allEvents []*events.Event

	// Get email date
	var emailDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		emailDate = email.ParseDate(dateHeaders[0])
	}

	// Create events for URLs
	for url := range urls {
		event := events.NewEvent("friendmts")
		event.EventDate = emailDate
		event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}
		event.URL = url
		allEvents = append(allEvents, event)
	}

	// Create events for IPs
	for ip := range ips {
		event := events.NewEvent("friendmts")
		event.EventDate = emailDate
		event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}
		event.IP = ip
		allEvents = append(allEvents, event)
	}

	return allEvents, nil
}

// parseDisneyCopyright handles Disney copyright reports
func (p *Parser) parseDisneyCopyright(bodyLower string) ([]*events.Event, error) {
	event := events.NewEvent("friendmts")

	// Extract event date
	dateStr := common.FindStringWithoutMarkers(bodyLower, "this access was present on", ".")
	event.EventDate = email.ParseDate(dateStr)

	// Extract copyrighted work
	copyrightedWork := common.GetNonEmptyLineAfter(bodyLower, "copyrighted work(s) infringed upon:")

	// Set copyright event type with Disney as owner
	event.EventTypes = []events.EventType{events.NewCopyright(copyrightedWork, "Disney Enterprises, Inc.", "")}

	// Extract URL
	url := common.GetNonEmptyLineAfter(bodyLower, "location of infringing material:")

	// Extract incident ID
	incidentID := strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "incident id", ""))
	if incidentID != "" {
		event.AddEventDetail(&events.ExternalID{ID: incidentID})
	}

	// Only return event if URL is valid
	if common.IsURL(url) {
		event.URL = url
		return []*events.Event{event}, nil
	}

	return []*events.Event{}, nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, _ := common.GetSubject(serializedEmail, false)
	subject = strings.ReplaceAll(subject, getLinebreak(subject), "")

	body, _ := common.GetBody(serializedEmail, false)
	// Fix common typo
	body = strings.ReplaceAll(body, "Adress", "Address")
	bodyLower := strings.ToLower(body)

	// Get from address
	var fromAddr string
	if envFrom := serializedEmail.Metadata.EnvelopeFrom; envFrom != "" {
		fromAddr = envFrom
	}

	// Check for escalated subjects
	escalatedSubjects := []string{
		"Urgent live stream escalation",
		"Urgent live stream copyright infringement escalation for",
		"Urgent live stream escalation for",
		"Urgent non-live stream escalation for",
		"Urgent Copyright Infringement Notice",
		"Copyright infringement notice",
	}

	for _, esub := range escalatedSubjects {
		if strings.Contains(subject, esub) {
			return p.parseEscalatedCopyrightInfringement(serializedEmail, subject, body, fromAddr)
		}
	}

	// Check for live stream copyright infringement
	if strings.Contains(subject, "URGENT - Live stream copyright infringement notification for") {
		return p.parseCopyrightInfringement(serializedEmail, subject, body, fromAddr)
	}

	// Check for future event reports (ignore)
	if strings.Contains(body, "will continue to use your infrastructure") {
		// Log warning and return empty list
		return []*events.Event{}, nil
	}

	// Check for sites/ips format
	if strings.Contains(bodyLower, "sites:") && strings.Contains(bodyLower, "ips:") && strings.Contains(bodyLower, "copyright") {
		return p.parseSimpleCopyright(serializedEmail, body, "sites:", "ips:", "ips:", "kind regards")
	}

	// Check for url's/ip addresses format
	if strings.Contains(bodyLower, "url's associated:") && strings.Contains(bodyLower, "ip addresses associated:") && strings.Contains(bodyLower, "copyright") {
		return p.parseSimpleCopyright(serializedEmail, body, "url's associated:", "ip addresses associated:", "ip addresses associated:", "we trust")
	}

	// Check for Disney copyright
	if strings.Contains(bodyLower, "disney enterprises") {
		return p.parseDisneyCopyright(bodyLower)
	}

	// Unknown format
	return nil, common.NewNewTypeError(subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
