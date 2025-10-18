package brandmonitor

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	// Pattern to match fraudulent website URLs in the body
	urlPattern = regexp.MustCompile(`(?i)fraudulent website( reported)*:*\s*(\*)*\s*(?P<url>http\S+)`)
)

// New creates a new brandmonitor parser (wrapper for bento-parsers compatibility)
func New(serializedEmail email.SerializedEmail, fromAddr, fromName, contentType string) *Parser {
	return NewParser()
}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get body and subject
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("no email body found")
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		subject = ""
	}

	subjectLower := strings.ToLower(subject)
	bodyLower := strings.ToLower(body)

	// Create event
	event := events.NewEvent("brandmonitor")

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Determine event type - check for trademark in subject or body
	if strings.Contains(subjectLower, "trademark") || strings.Contains(bodyLower, "trademark") {
		event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}
	} else {
		// If not trademark, return error for new type (as in Python)
		return nil, common.NewParserError("unknown event type in subject: " + subjectLower)
	}

	// Try to extract IP from subject (Python does this but doesn't use a proper function)
	// The Python code tries to set event.ip = subject_lower which would fail unless
	// subject_lower is a valid IP. This seems like legacy code, so we'll try to extract IP properly.
	if ip := common.ExtractOneIP(subjectLower); ip != "" {
		event.IP = ip
	}

	// Extract URL from body
	// First try the regex pattern
	if matches := urlPattern.FindStringSubmatch(body); len(matches) > 0 {
		// Find the named group 'url'
		for i, name := range urlPattern.SubexpNames() {
			if name == "url" && i < len(matches) {
				event.URL = matches[i]
				break
			}
		}
	} else {
		// If regex didn't match, try FindStringWithoutMarkers
		if url := common.FindStringWithoutMarkers(body, "website", "is unlawfully"); url != "" {
			event.URL = url
		}
	}

	// Only yield event if we have IP or URL (as in Python)
	if event.IP != "" || event.URL != "" {
		return []*events.Event{event}, nil
	}

	return nil, common.NewParserError("no IP or URL found in email")
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
