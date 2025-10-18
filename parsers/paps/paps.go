package paps

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
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

	// Get date from email headers
	var dateStr string
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateStr = dateHeaders[0]
	}
	eventDate := email.ParseDate(dateStr)

	// Extract data between [URL] and [/URL] markers
	dataLines := common.FindStringWithoutMarkers(body, "URL]", "[/URL]")

	// Split lines and categorize into URL candidates and IP candidates
	urlCandidates := make(map[string]bool)
	ipCandidates := make(map[string]bool)

	for _, line := range strings.Split(dataLines, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(line, "http") {
			urlCandidates[line] = true
		} else if strings.Count(line, ".") == 3 {
			ipCandidates[line] = true
		}
	}

	// Remove URLs from IP candidates
	for url := range urlCandidates {
		delete(ipCandidates, url)
	}

	// Extract one IP from the remaining candidates
	var ip string
	for candidate := range ipCandidates {
		ip = common.ExtractOneIP(candidate)
		if ip != "" {
			break
		}
	}

	// Create events for each URL
	var eventsList []*events.Event
	for url := range urlCandidates {
		if strings.HasPrefix(url, "http") {
			event := events.NewEvent("paps")
			event.EventDate = eventDate
			event.EventTypes = []events.EventType{events.NewChildAbuse()}
			event.URL = url
			event.IP = ip
			eventsList = append(eventsList, event)
		}
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
