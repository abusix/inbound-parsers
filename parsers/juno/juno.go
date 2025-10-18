// Package juno implements the Juno parser for spam reports
package juno

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the Juno parser
type Parser struct{}

var (
	ipPattern    = regexp.MustCompile(`remove your[^.]*(terrorist|spammer)[^.]*at:(.*)`)
	urlPattern   = regexp.MustCompile(`(spammer's|terrorist's|thief's)[^.]*web[^.]*page[^.]*at:(.*)`)
	emailPattern = regexp.MustCompile(`(spammer's|terrorist's|thief's )[^.]*mail[^.]*service[^.]*at:[^\r](.*)`)
)

// Parse parses emails from dxcluster@juno.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, _ := common.GetSubject(serializedEmail, false)

	bodyLower := strings.ToLower(body)

	// Check if this is a spam report
	if !strings.Contains(bodyLower, "spam") {
		return nil, common.NewNewTypeError(subject)
	}

	// Split at forwarded message marker if present
	marker := "-------- forwarded message --------"
	if strings.Contains(bodyLower, marker) {
		parts := strings.Split(bodyLower, marker)
		bodyLower = parts[0]
	}

	return parseSpam(bodyLower, serializedEmail)
}

func parseSpam(bodyLower string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	var evts []*events.Event

	// Extract IP address
	ip := ""
	if ipMatch := ipPattern.FindStringSubmatch(bodyLower); len(ipMatch) > 2 {
		ip = strings.TrimSpace(ipMatch[2])
	}

	// Extract URLs
	var urls []string
	urlMatches := urlPattern.FindAllStringSubmatch(bodyLower, -1)
	for _, match := range urlMatches {
		if len(match) > 2 {
			url := strings.TrimSpace(match[2])
			if url != "" {
				urls = append(urls, url)
			}
		}
	}

	// Extract email addresses
	var eligibleMails []string
	emailMatches := emailPattern.FindAllStringSubmatch(bodyLower, -1)
	for _, match := range emailMatches {
		if len(match) > 2 {
			mailAddr := strings.TrimSpace(match[2])
			// Filter out empty values
			if mailAddr != "" && mailAddr != "\n" && mailAddr != "\r" {
				eligibleMails = append(eligibleMails, mailAddr)
			}
		}
	}

	// Create SpammerMails event detail
	spammerMails := &events.SpammerMails{
		Addresses: eligibleMails,
	}

	// Get date from email header
	var eventDate *string
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = &dateHeaders[0]
	}

	// Create event for each URL
	for _, url := range urls {
		event := createEvent(ip, url, eventDate, spammerMails)
		evts = append(evts, event)
	}

	// If no URLs but IP exists, create one event
	if len(urls) == 0 && ip != "" {
		event := createEvent(ip, "", eventDate, spammerMails)
		evts = append(evts, event)
	}

	if len(evts) == 0 {
		return nil, common.NewParserError("no spam events found")
	}

	return evts, nil
}

func createEvent(ip, url string, eventDate *string, spammerMails *events.SpammerMails) *events.Event {
	event := events.NewEvent("juno")

	if ip != "" {
		event.IP = ip
	}

	if url != "" {
		event.URL = url
	}

	event.EventTypes = []events.EventType{events.NewSpam()}

	if eventDate != nil {
		event.EventDate = email.ParseDate(*eventDate)
	}

	event.AddEventDetail(spammerMails)

	return event
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
