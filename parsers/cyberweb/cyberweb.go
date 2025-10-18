package cyberweb

import (
	"encoding/json"
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

// Parse implements parsing for cyberweb (authsendking@cyberweb.com.br)
// This parser handles:
// 1. XARF JSON attachments (xarf-report.json)
// 2. Login attack / brute force reports from email body/subject
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// First, try to find and parse XARF JSON attachment
	if attachment, err := common.FindFirstAttachmentWithMimeType(serializedEmail, "xarf-report.json"); err == nil {
		if event, err := p.parseXARFAttachment(attachment); err == nil {
			return []*events.Event{event}, nil
		}
		// If XARF parsing fails, fall through to regular parsing
	}

	// If no XARF attachment or parsing failed, parse from body/subject
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)

	// Check if this is a login attack / brute force report
	if strings.Contains(subjectLower, "loginattack") || strings.Contains(bodyLower, "bruteforce attack") {
		event := events.NewEvent("cyberweb")
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

		// Try to extract event date from body using pattern: YYYY-MM-DDThh:mm:ss
		datePattern := regexp.MustCompile(`(?P<date>\d{4}-\d{2}-\d{2})t(?P<time>\d{2}:\d{2}:\d{2})`)
		if matches := datePattern.FindStringSubmatch(bodyLower); matches != nil {
			// Combine date and time parts (matches[1] is date, matches[2] is time)
			if len(matches) >= 3 {
				dateTimeStr := matches[1] + " " + matches[2]
				event.EventDate = email.ParseDate(dateTimeStr)
			}
		}

		// If no date found in body, use email header date
		if event.EventDate == nil {
			if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
				event.EventDate = email.ParseDate(dateHeaders[0])
			}
		}

		// Extract IP from subject
		// The Python version sets event.ip = subject_lower, which seems to expect
		// the subject to contain an IP address
		if ip := common.ExtractOneIP(subjectLower); ip != "" {
			event.IP = ip
		}

		return []*events.Event{event}, nil
	}

	// If we get here, it's a new/unknown report type
	return nil, &common.ParserError{Message: "Unknown report type: " + subjectLower}
}

// parseXARFAttachment attempts to parse a XARF JSON attachment
// Since there's no full XARF conversion utility yet in Go, this is a simplified
// implementation that extracts basic fields
func (p *Parser) parseXARFAttachment(attachmentData string) (*events.Event, error) {
	var xarfData map[string]interface{}
	if err := json.Unmarshal([]byte(attachmentData), &xarfData); err != nil {
		return nil, err
	}

	event := events.NewEvent("cyberweb")

	// Try to extract basic XARF fields
	// This is a simplified version - full XARF parsing would be more complex
	if reportType, ok := xarfData["Report-Type"].(string); ok {
		switch strings.ToLower(reportType) {
		case "login-attack":
			event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
		case "abuse":
			event.EventTypes = []events.EventType{events.NewSpam()}
		case "fraud":
			event.EventTypes = []events.EventType{events.NewPhishing()}
		default:
			event.EventTypes = []events.EventType{events.NewUnknown()}
		}
	}

	// Extract IP
	if sourceIP, ok := xarfData["Source-IP"].(string); ok {
		event.IP = sourceIP
	} else if sourceIP, ok := xarfData["Source"].(string); ok {
		event.IP = sourceIP
	}

	// Extract date
	if date, ok := xarfData["Date"].(string); ok {
		event.EventDate = email.ParseDate(date)
	}

	// Extract URL if present
	if url, ok := xarfData["Reported-Uri"].(string); ok {
		event.URL = url
	}

	return event, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
