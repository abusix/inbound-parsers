package iwf

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

var colonKeyValueRegex = regexp.MustCompile(`([^:]+):\s*(.*)[\r\n]?`)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	var eventDate *time.Time
	var ip string
	var serial string
	var reason string
	var password string
	var remarks string
	var refControl string
	urls := make(map[string]bool)

	// Parse colon-separated key-value pairs
	for key, value := range colonKeyValueGenerator(body) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		keyLower := strings.ToLower(strings.TrimSpace(key))

		switch {
		case strings.Contains(keyLower, "url remarks"):
			remarks = strings.Trim(value, "[]")
		case keyLower == "url":
			url := common.CleanURL(value)
			urls[url] = true
		case keyLower == "iwf serial number":
			serial = value
		case keyLower == "reason code":
			reason = value
		case keyLower == "password":
			password = value
		case keyLower == "ip address":
			ip = common.ExtractOneIP(value)
		case keyLower == "time assessed":
			// Python adds ":00" to the time string
			eventDate = email.ParseDate(value + ":00")
		case keyLower == "ref control":
			refControl = value
		}
	}

	// Fallback to email header date if not found
	if eventDate == nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// URL is required
	if len(urls) == 0 {
		return nil, common.NewParserError("url is missing")
	}

	// Add more URLs from "Also URLs:" section
	additionalURLs := common.GetContinuousLinesUntilEmptyLine(body, "Also URLs:")
	for _, url := range additionalURLs {
		cleanedURL := common.CleanURL(strings.TrimSpace(url))
		if cleanedURL != "" {
			urls[cleanedURL] = true
		}
	}

	// Create an event for each URL
	var eventsList []*events.Event
	for url := range urls {
		event := events.NewEvent("iwf")
		event.EventTypes = []events.EventType{events.NewChildAbuse()}

		// Add password detail
		event.AddEventDetail(&events.Password{
			PasswordHash: password,
		})

		// Add simple event details
		event.AddEventDetailSimple("reason_code", reason)
		event.AddEventDetailSimple("iwf_serial_number", serial)
		event.AddEventDetailSimple("ref_control", refControl)
		event.AddEventDetailSimple("remarks", remarks)

		// Set event fields
		event.EventDate = eventDate
		event.IP = ip
		event.URL = url

		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

// colonKeyValueGenerator extracts key-value pairs from colon-separated text
func colonKeyValueGenerator(text string) map[string]string {
	result := make(map[string]string)
	matches := colonKeyValueRegex.FindAllStringSubmatch(text, -1)
	for _, match := range matches {
		if len(match) == 3 {
			key := strings.TrimSpace(match[1])
			value := strings.TrimSpace(match[2])
			result[key] = value
		}
	}
	return result
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
