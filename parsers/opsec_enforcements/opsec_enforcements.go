package opsec_enforcements

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

var (
	ipPattern  = regexp.MustCompile(`(?i)(whois record information:)[^.0-9]*(\d{0,3}\.\d{0,3}\.\d{0,3}\.\d{0,3})`)
	urlPattern = regexp.MustCompile(`https?://[^ \n]*`)
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	bodyLower, _ := common.GetBody(serializedEmail, false)
	bodyLower = strings.ToLower(bodyLower)

	subjectLower, _ := common.GetSubject(serializedEmail, false)
	subjectLower = strings.ToLower(subjectLower)

	// Get date from headers
	date := email.ParseDate(serializedEmail.Headers["date"][0])

	// Determine type based on subject and body
	if strings.Contains(subjectLower, "copyright") {
		return p.parseCopyright(bodyLower, subjectLower, date)
	}

	if strings.Contains(subjectLower, "trademark") || strings.Contains(bodyLower, "trademark") {
		return p.parseTrademark(bodyLower, subjectLower, date)
	}

	return nil, fmt.Errorf("unknown message type: %s", subjectLower)
}

func (p *Parser) getExternalID(subject string) string {
	return common.FindStringWithoutMarkers(subject, "ecin:", "]")
}

func (p *Parser) getURL(subject, startMarker string) string {
	// Replace carriage returns and newlines
	cleanSubject := strings.ReplaceAll(subject, "\r", "")
	cleanSubject = strings.ReplaceAll(cleanSubject, "\n", "")
	return common.FindStringWithoutMarkers(cleanSubject, startMarker, "[")
}

func (p *Parser) parseCopyright(body, subject string, date *time.Time) ([]*events.Event, error) {
	var result []*events.Event

	cprOwner := "texas instruments incorporated"
	copyrightOwner := ""
	if strings.Contains(body, cprOwner) {
		copyrightOwner = strings.Title(cprOwner)
	}

	// Find all URLs in body
	urls := urlPattern.FindAllString(body, -1)
	for _, url := range urls {
		event := events.NewEvent("opsec_enforcements")

		// Create copyright event type
		copyright := events.NewCopyright("", copyrightOwner, "")
		event.EventTypes = []events.EventType{copyright}
		event.EventDate = date
		event.URL = url

		// Add external ID as event detail
		if externalID := p.getExternalID(subject); externalID != "" {
			event.AddEventDetail(&events.ExternalID{ID: externalID})
		}

		result = append(result, event)
	}

	return result, nil
}

func (p *Parser) parseTrademark(body, subject string, date *time.Time) ([]*events.Event, error) {
	event := events.NewEvent("opsec_enforcements")

	// Try to extract URL from subject
	markers := []string{"- warning letter", "- "}
	for _, marker := range markers {
		if url := p.getURL(subject, marker); url != "" {
			// Add protocol if missing
			if !strings.Contains(url, "http") && !strings.Contains(url, "hxxp") {
				url = "http://" + strings.TrimSpace(url)
			}
			event.URL = url
			break
		}
	}

	// Try to extract IP
	if match := ipPattern.FindStringSubmatch(body); match != nil && len(match) > 2 {
		// Validate IP address before setting
		ip := match[2]
		// Basic validation - check if it looks like a valid IP
		parts := strings.Split(ip, ".")
		if len(parts) == 4 {
			event.IP = ip
		}
	}

	// Only create event if we found IP or URL
	if event.IP != "" || event.URL != "" {
		event.EventDate = date

		// Extract trademark owner
		trademarkOwner := ""
		if owner := common.FindStringWithoutMarkers(body, "on behalf of ", ""); owner != "" {
			// Split on 'trademarks' and take the first part
			if idx := strings.Index(owner, "trademarks"); idx != -1 {
				owner = owner[:idx]
			}
			trademarkOwner = strings.TrimSpace(owner)
			trademarkOwner = strings.Title(trademarkOwner)
		}

		// Create trademark event type
		trademark := events.NewTrademark("", nil, trademarkOwner, "")
		event.EventTypes = []events.EventType{trademark}

		// Add external ID as event detail
		if externalID := p.getExternalID(subject); externalID != "" {
			event.AddEventDetail(&events.ExternalID{ID: externalID})
		}

		return []*events.Event{event}, nil
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
