// Package names_uk implements the names.co.uk parser
package names_uk

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the names_uk parser
type Parser struct{}

var (
	urlPattern  = regexp.MustCompile(`(?i)((phishing\/malware page at :)[^h.]*(?P<url>\S+))`)
	datePattern = regexp.MustCompile(`(?i)((sent on )(?P<date>[^,]*))`)
)

// Parse parses emails from @names.co.uk
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Get date fallback
	dateFallback := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateFallback = dateHeaders[0]
	}

	if strings.Contains(strings.ToLower(subject), "phishing") {
		return parsePhishing(body, subject, dateFallback)
	}

	return nil, common.NewNewTypeError(subject)
}

func parsePhishing(body, subject, dateFallback string) ([]*events.Event, error) {
	event := events.NewEvent("names_uk")

	// Set event date
	eventDate := email.ParseDate(dateFallback)
	event.EventDate = eventDate

	// Set event type
	event.EventTypes = []events.EventType{events.NewPhishing()}

	// Try to extract IP from subject
	ip := common.ExtractOneIP(subject)
	if ip != "" {
		event.IP = ip
	}

	// Extract URL from body
	if match := urlPattern.FindStringSubmatch(body); len(match) > 3 {
		event.URL = match[3]
	}

	// Only return event if we have an IP or URL
	if event.IP != "" || event.URL != "" {
		return []*events.Event{event}, nil
	}

	return nil, common.NewParserError("No IP or URL found in names_uk parser")
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
