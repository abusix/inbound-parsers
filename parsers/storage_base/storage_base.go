package storage_base

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

var (
	// DATE_PATTERN_1: generated at Mon 12 Jan 2024 12:30:45 PM UTC
	datePattern1 = regexp.MustCompile(`(?i)generated at \b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?P<year>\d{4})\s+\d{2}:\d{2}:\d{2}\s+(?:AM|PM)\s+[A-Z]+\b`)
	// DATE_PATTERN_2: generated at Mon Jan 12 12:30:45 PM UTC 2024
	datePattern2 = regexp.MustCompile(`(?i)generated at \b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(?:AM|PM)\s+[A-Z]+\s+(?P<year>\d{4})\b`)
	// DATE_PATTERN_3: 2024-01-12T12:30:45.123456+00:00
	datePattern3 = regexp.MustCompile(`(?i)(?P<date>\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}[+-]\d{2}:\d{2}\b)`)
)

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	body = strings.ToLower(body)

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	subject = strings.ToLower(subject)

	// Get date fallback from headers
	var dateFallback *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateFallback = email.ParseDate(dateHeaders[0])
	}

	var eventType events.EventType
	var year string

	if strings.Contains(subject, "mail login bruteforce") {
		eventType = events.NewLoginAttack("", "")
		// Extract year from "generated at " line
		yearLine := common.FindStringWithoutMarkers(body, "generated at ", "")
		parts := strings.Fields(yearLine)
		if len(parts) > 0 {
			year = parts[len(parts)-1]
		}
	} else if strings.Contains(subject, "spam") {
		eventType = events.NewSpam()
		// Replace ^ followed by [ or ] with ########## at the start of lines
		body = regexp.MustCompile(`(?m)^(\[|\])`).ReplaceAllString(body, "##########")

		// Try to extract year from date patterns
		if match := datePattern1.FindStringSubmatch(body); match != nil {
			year = match[datePattern1.SubexpIndex("year")]
		} else if match := datePattern2.FindStringSubmatch(body); match != nil {
			year = match[datePattern2.SubexpIndex("year")]
		}
	} else {
		return nil, fmt.Errorf("unknown subject type: %s", subject)
	}

	// Extract IP address
	ip := common.FindStringWithoutMarkers(body, "ip address ", " generated")

	// Restore the replacement for processing log block
	body = strings.ReplaceAll(body, "##########", "##########\n")

	// Get block after ##########
	logBlock := common.GetBlockAfterWithStop(body, "##########", "")
	if len(logBlock) == 0 {
		return nil, fmt.Errorf("no log block found")
	}

	// Only get first log line since we only want precise event_date
	line := logBlock[0]
	line = strings.Trim(line, "\"")
	line = regexp.MustCompile(`\s+`).ReplaceAllString(line, " ")

	event := events.NewEvent("storage_base")

	// Try to parse date from ISO format first
	if match := datePattern3.FindStringSubmatch(body); match != nil {
		dateStr := match[datePattern3.SubexpIndex("date")]
		if inputDatetime, err := time.Parse(time.RFC3339, dateStr); err == nil {
			// Convert to the format: Mon Jan 02 15:04:05 2006
			event.EventDate = &inputDatetime
		} else if dateFallback != nil {
			event.EventDate = dateFallback
		}
	} else {
		// Parse date from log line
		parts := strings.Fields(line)
		if len(parts) >= 3 && year != "" {
			dateStr := fmt.Sprintf("%s %s %s %s", parts[0], parts[1], parts[2], year)
			if parsed, err := time.Parse("Jan 2 15:04:05 2006", dateStr); err == nil {
				event.EventDate = &parsed
			} else if dateFallback != nil {
				event.EventDate = dateFallback
			}
		} else if dateFallback != nil {
			event.EventDate = dateFallback
		}
	}

	event.EventTypes = []events.EventType{eventType}
	event.IP = ip

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
