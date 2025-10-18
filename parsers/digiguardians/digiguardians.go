package digiguardians

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	// WORK_MATCHER regex pattern to extract copyrighted work
	workMatcher = regexp.MustCompile(`is\s+our\s+(movie|art\s+work)\s+\W*(?P<movie>.*?)\W+\s+released\s+worldwide`)

	// colonKeyValuePattern matches "key: value" patterns
	colonKeyValuePattern = regexp.MustCompile(`(\w+):\s*(.*)[\r\n]?`)
)

func NewParser() *Parser {
	return &Parser{}
}

// colonKeyValueGenerator yields key-value pairs from colon-delimited text
func colonKeyValueGenerator(text string) [][2]string {
	var results [][2]string
	matches := colonKeyValuePattern.FindAllStringSubmatch(text, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			key := strings.TrimSpace(match[1])
			value := strings.TrimSpace(match[2])
			results = append(results, [2]string{key, value})
		}
	}
	return results
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get date from headers
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	// Get subject
	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		subject = ""
	}

	// Get body
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Normalize line endings
	body = strings.ReplaceAll(body, "\r", "\n")

	// Validate subject and body content
	if !strings.Contains(subject, "Copyright Claim") &&
		!strings.Contains(body, "Online Copyright Infringement Liability Limitation Act") {
		return nil, common.NewNewTypeError(subject)
	}

	// Extract copyrighted work
	var copyrightedWork string

	// Try first pattern: is our movie <b>'...'
	movieStr := common.FindString(body, "is our movie <b>'", "'")
	if movieStr != "" {
		// Extract the value between the quotes
		parts := strings.Split(movieStr, "'")
		if len(parts) >= 2 {
			copyrightedWork = parts[1]
		}
	}

	// If not found, try regex pattern
	if copyrightedWork == "" {
		matches := workMatcher.FindStringSubmatch(body)
		if len(matches) == 0 {
			return nil, common.NewParserError("copyrighted work not found")
		}
		// Extract the named group 'movie'
		for i, name := range workMatcher.SubexpNames() {
			if name == "movie" && i < len(matches) {
				copyrightedWork = matches[i]
				break
			}
		}
	}

	// Initialize variables
	var urls []string
	var organisation *events.Organisation
	copyrightOwner := ""

	// Parse key-value pairs from body
	for _, pair := range colonKeyValueGenerator(body) {
		key := strings.ToLower(pair[0])
		value := pair[1]

		switch key {
		case "reference":
			// Extract URLs from the reference field
			urlsStr := common.FindString(value, "href=\"", "\"")
			if urlsStr != "" {
				// Remove the markers and split by <br />
				urlsStr = strings.TrimPrefix(urlsStr, "href=\"")
				urlsStr = strings.TrimSuffix(urlsStr, "\"")
				urls = strings.Split(urlsStr, "<br />")
			} else {
				// No href found, just use the value
				urlValue := strings.ReplaceAll(value, "<br />", "")
				urls = []string{urlValue}
			}
		case "owners":
			copyrightOwner = value
		case "claim":
			// Parse organization info from claim field
			// Format: "address + phone, email, http://url"
			organisation = &events.Organisation{
				Name: "reporter",
			}

			// Extract address (before the last comma before '+')
			addressPart := value
			if plusIdx := strings.Index(value, "+"); plusIdx != -1 {
				beforePlus := value[:plusIdx]
				if commaIdx := strings.LastIndex(beforePlus, ","); commaIdx != -1 {
					addressPart = beforePlus[:commaIdx]
				}
			}
			organisation.Address = strings.TrimSpace(addressPart)

			// Parse fields separated by commas
			fields := strings.Split(value, ",")
			for _, field := range fields {
				field = strings.TrimSpace(field)
				if strings.Contains(field, "+") {
					organisation.ContactPhone = field
				}
				if strings.Contains(field, "@") {
					organisation.ContactEmail = field
				}
				if strings.Contains(field, "http") {
					organisation.URLOrDomain = field
				}
			}
		}
	}

	// Validate that we found URLs
	if len(urls) == 0 {
		return nil, common.NewParserError("no url found")
	}

	// Create events for each URL
	var eventsResult []*events.Event
	eventType := events.NewCopyright(copyrightedWork, copyrightOwner, "")

	for _, url := range urls {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}

		event := events.NewEvent("digiguardians")
		event.EventDate = eventDate
		event.URL = url
		event.EventTypes = []events.EventType{eventType}

		if organisation != nil {
			event.AddEventDetail(organisation)
		}

		eventsResult = append(eventsResult, event)
	}

	// Validate we created at least one event
	if len(eventsResult) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return eventsResult, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
