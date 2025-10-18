package stockpile

import (
	"fmt"
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
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Check for CSV attachment
	partType := ""
	if len(serializedEmail.Parts) > 1 {
		if serializedEmail.Parts[1].Headers != nil {
			if ct, ok := serializedEmail.Parts[1].Headers["content-type"]; ok && len(ct) > 0 {
				partType = ct[0]
			}
		}
	}

	if strings.Contains(partType, "csv") {
		// Parse CSV attachment
		if len(serializedEmail.Parts) > 1 {
			csvContent := ""
			switch body := serializedEmail.Parts[1].Body.(type) {
			case string:
				csvContent = body
			case []byte:
				csvContent = string(body)
			default:
				return nil, common.NewParserError("unexpected part body type")
			}
			return parseCSVAttachment(csvContent, subject)
		}
	} else if strings.Contains(strings.ToLower(body), "our ip's are performing a credential stuffing attack on our server") {
		// Parse table format
		return parseTable(serializedEmail, body, subject)
	} else if strings.Contains(strings.ToLower(body), "ip's from your asn") {
		// Parse single ASN format
		return parseSingleASN(serializedEmail, body, subject)
	}

	return nil, common.NewNewTypeError(subject)
}

func parseCSVAttachment(content, subject string) ([]*events.Event, error) {
	// Extract target URL from subject: "http" + subject.split('http')[1]
	if !strings.Contains(subject, "http") {
		return nil, common.NewParserError("no URL in subject")
	}

	parts := strings.SplitN(subject, "http", 2)
	if len(parts) < 2 {
		return nil, common.NewParserError("failed to extract URL from subject")
	}
	targetURL := "http" + parts[1]

	var eventsList []*events.Event
	lines := strings.Split(content, "\n")

	// Skip header line (index 0)
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) < 5 {
			continue
		}

		// parts[4] contains date and time like "10/18/2025 14:30:45"
		dateTimeParts := strings.Fields(parts[4])
		if len(dateTimeParts) < 2 {
			continue
		}

		// Parse date: "10/18/2025" -> "2025-10-18"
		dateParts := strings.Split(dateTimeParts[0], "/")
		if len(dateParts) != 3 {
			continue
		}
		// Ensure zero padding
		month := padZero(dateParts[0])
		day := padZero(dateParts[1])
		year := dateParts[2]
		dateStr := fmt.Sprintf("%s-%s-%s", year, month, day)

		// Parse time: "14:30:45" -> "14:30:45" (with zero padding)
		timeParts := strings.Split(dateTimeParts[1], ":")
		if len(timeParts) != 3 {
			continue
		}
		hour := padZero(timeParts[0])
		minute := padZero(timeParts[1])
		second := padZero(timeParts[2])
		timeStr := fmt.Sprintf("%s:%s:%s", hour, minute, second)

		// Combine date and time
		eventDateStr := fmt.Sprintf("%s %s", dateStr, timeStr)

		// Parse the datetime
		eventDate, err := time.Parse("2006-01-02 15:04:05", eventDateStr)
		if err != nil {
			continue
		}

		event := events.NewEvent("stockpile")
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
		event.IP = strings.TrimSpace(parts[0])
		event.EventDate = &eventDate
		event.AddEventDetail(&events.Target{URL: targetURL})

		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

func parseTable(serializedEmail *email.SerializedEmail, body, subject string) ([]*events.Event, error) {
	if !strings.Contains(body, "clientip clientasn _count") {
		return nil, common.NewParserError("header changed, adapt the parser")
	}

	// Extract target URL from subject: "servers at" followed by the URL
	if !strings.Contains(subject, "servers at") {
		return nil, common.NewParserError("no 'servers at' in subject")
	}

	parts := strings.SplitN(subject, "servers at", 2)
	if len(parts) < 2 {
		return nil, common.NewParserError("failed to extract URL from subject")
	}
	targetURL := strings.TrimSpace(parts[1])

	// Get event date from email headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	var eventsList []*events.Event

	// Get block around the header marker
	entries := common.GetBlockAround(body, "clientip clientasn _count")

	// Skip the header line (first entry)
	for i := 1; i < len(entries); i++ {
		fields := strings.Fields(entries[i])
		if len(fields) < 3 {
			continue
		}

		ip := fields[0]
		asn := fields[1]

		event := events.NewEvent("stockpile")
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
		event.EventDate = eventDate
		event.IP = ip
		event.AddEventDetail(&events.ASN{ASN: asn})
		event.AddEventDetail(&events.Target{URL: targetURL})

		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

func parseSingleASN(serializedEmail *email.SerializedEmail, body, subject string) ([]*events.Event, error) {
	// Extract ASN: "from your ASN " + asn
	asn := common.FindStringWithoutMarkers(body, "from your ASN ", " ")
	if asn == "" {
		return nil, common.NewParserError("failed to extract ASN")
	}

	// Extract target URL from subject: "servers at" followed by the URL
	if !strings.Contains(subject, "servers at") {
		return nil, common.NewParserError("no 'servers at' in subject")
	}

	parts := strings.SplitN(subject, "servers at", 2)
	if len(parts) < 2 {
		return nil, common.NewParserError("failed to extract URL from subject")
	}
	targetURL := strings.TrimSpace(parts[1])

	// Get event date from email headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	var eventsList []*events.Event

	// Get block of IPs after "from your ASN"
	ips := common.GetBlockAfterWithStop(body, "from your ASN", "")

	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}

		event := events.NewEvent("stockpile")
		event.IP = ip
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
		event.EventDate = eventDate
		event.AddEventDetail(&events.ASN{ASN: asn})
		event.AddEventDetail(&events.Target{URL: targetURL})

		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

// padZero pads a numeric string with a leading zero if needed
func padZero(s string) string {
	s = strings.TrimSpace(s)
	if len(s) == 1 {
		return "0" + s
	}
	return s
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
