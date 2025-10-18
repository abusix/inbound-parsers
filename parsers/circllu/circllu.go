package circllu

import (
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	// Determine event type based on subject
	var eventType events.EventType
	if strings.Contains(subjectLower, "phishing") {
		eventType = events.NewPhishing()
	} else if strings.Contains(subjectLower, "malicious files") {
		eventType = events.NewMalwareHosting()
	} else {
		return nil, common.NewParserError("unknown event type in subject: " + subject)
	}

	// Get external ID from X-RT-Ticket header or subject
	var extID string
	if rtTicket, ok := serializedEmail.Headers["X-RT-Ticket"]; ok && len(rtTicket) > 0 {
		extID = common.FindStringWithoutMarkers(rtTicket[0], "#", "]")
	} else {
		extID = common.FindStringWithoutMarkers(subject, "#", "]")
	}

	// Get event date from date header
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	body = strings.ReplaceAll(body, "\r\n", "\n")

	// Find report block and split into individual blocks
	reportBlock := findReportBlock(body)
	if reportBlock == nil {
		return nil, common.NewParserError("no report block found")
	}

	blocks := splitIntoBlocks(reportBlock)
	var allEvents []*events.Event

	for _, block := range blocks {
		evts := parseCirclBlock(block, eventType, eventDate, extID)
		allEvents = append(allEvents, evts...)
	}

	if len(allEvents) == 0 {
		return nil, common.NewParserError("no events found in report")
	}

	return allEvents, nil
}

// findReportBlock finds the report section of the full report.
// It is contained by two empty lines and then starts with a URL.
// It ends with two empty lines
func findReportBlock(body string) []string {
	var block []string
	continuousEmpty := 0

	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			continuousEmpty = 0
			if len(block) > 0 || strings.HasPrefix(trimmed, "hXXp") || strings.HasPrefix(trimmed, "http") {
				block = append(block, line)
			}
		} else {
			continuousEmpty++
			if len(block) > 0 {
				if continuousEmpty >= 2 {
					return block
				}
				block = append(block, line)
			}
		}
	}

	if len(block) > 0 {
		return block
	}
	return nil
}

// splitIntoBlocks splits the report block into individual event blocks
func splitIntoBlocks(body []string) []string {
	var blocks []string
	var block []string

	for _, line := range body {
		if strings.TrimSpace(line) != "" {
			block = append(block, line)
		} else if len(block) > 0 {
			blocks = append(blocks, strings.Join(block, "\n"))
			block = nil
		}
	}

	if len(block) > 0 {
		blocks = append(blocks, strings.Join(block, "\n"))
	}

	return blocks
}

// parseCirclBlock parses a single CIRCL block into events
func parseCirclBlock(block string, eventType events.EventType, eventDate *time.Time, extID string) []*events.Event {
	var evts []*events.Event
	ipsMap := make(map[string]bool)

	// Remove newlines and split by tabs
	block = strings.ReplaceAll(block, "\n", "")
	lines := strings.Split(block, "\t")

	// Remove empty lines
	var cleanedLines []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			cleanedLines = append(cleanedLines, line)
		}
	}

	if len(cleanedLines) == 0 {
		return evts
	}

	// First line is the URL
	url := common.CleanURL(cleanedLines[0])

	// Extract IPs from remaining lines (index 1 is virustotal, skip it and process rest)
	for i := 1; i < len(cleanedLines); i++ {
		line := cleanedLines[i]
		line = strings.ReplaceAll(line, "[", "")
		line = strings.ReplaceAll(line, "]", "")
		if ip := common.ExtractOneIP(line); ip != "" {
			ipsMap[ip] = true
		}
	}

	// Create an event for each IP
	for ip := range ipsMap {
		evt := events.NewEvent("circllu")
		evt.EventDate = eventDate
		evt.URL = url
		evt.IP = ip

		if extID != "" {
			evt.AddEventDetail(&events.ExternalID{ID: extID})
		}

		// Clone the event type
		switch et := eventType.(type) {
		case *events.Phishing:
			phishing := events.NewPhishing()
			phishing.PhishingTarget = url
			evt.EventTypes = []events.EventType{phishing}
		case *events.MalwareHosting:
			evt.EventTypes = []events.EventType{events.NewMalwareHosting()}
		default:
			_ = et // Unused, but handles the type assertion
		}

		evts = append(evts, evt)
	}

	return evts
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
