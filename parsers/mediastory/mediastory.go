// Package mediastory implements the mediastory parser
// This is a 100% exact Go translation of Python's mediastory.py
package mediastory

import (
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the mediastory parser
type Parser struct{}

// New creates a new mediastory parser instance
func New() *Parser {
	return &Parser{}
}

// Parse parses emails from mediastory.co.kr and mediastory.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	bodyLower := strings.ToLower(body)

	fromAddr, err := common.GetFrom(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	var evts []*events.Event

	// Check for Disney Enterprise format
	if strings.Contains(bodyLower, "disney enterprise") {
		originalURL := common.GetNonEmptyLineAfter(bodyLower, "infringed upon:")
		if idx := strings.Index(originalURL, ")"); idx >= 0 {
			originalURL = strings.TrimSpace(originalURL[:idx])
		}

		locationStartLine := strings.TrimSpace(
			common.GetNonEmptyLineAfter(bodyLower, "location of infringing material:"),
		)
		copyrightOwner := "Disney Enterprises, Inc."
		evts, err = parseEvents(serializedEmail, originalURL, locationStartLine, copyrightOwner)
		if err != nil {
			return nil, err
		}

	} else if checkStringMatch([]string{"habin.lee", "gayeong.kim"}, fromAddr) {
		// habin.lee or gayeong.kim format
		originalURL := strings.TrimSpace(common.GetNonEmptyLineAfter(bodyLower, "at:"))

		locationStartLine := common.GetNonEmptyLineAfter(bodyLower, "can be found at:")
		// Split by 'content' or 'copy' and take the first part
		if idx := strings.Index(locationStartLine, "content"); idx >= 0 {
			locationStartLine = locationStartLine[:idx]
		}
		if idx := strings.Index(locationStartLine, "copy"); idx >= 0 {
			locationStartLine = locationStartLine[:idx]
		}
		locationStartLine = strings.TrimSpace(locationStartLine)

		evts, err = parseEvents(serializedEmail, originalURL, locationStartLine, "")
		if err != nil {
			return nil, err
		}

	} else if checkStringMatch([]string{"dahyun.lee", "hyelim.lim", "dayoung.kim", "taeeun.jin", "seongmin.an"}, fromAddr) {
		// HTML-based format
		bodyHTML, err := common.FindFirstAttachmentWithMimeType(serializedEmail, "html")
		if err != nil {
			return nil, err
		}

		// Parse HTML with goquery
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(bodyHTML))
		if err != nil {
			return nil, err
		}

		// Get text with newline separators
		bodySoupText := doc.Text()

		originalURL := strings.TrimSpace(
			common.GetNonEmptyLineAfter(bodySoupText, "exclusive rights, can be found at:"),
		)

		locationStartLine := strings.TrimSpace(
			common.GetNonEmptyLineAfter(bodyLower, "the unauthorized and infringing content can be found at:"),
		)

		evts, err = parseEvents(serializedEmail, originalURL, locationStartLine, "")
		if err != nil {
			return nil, err
		}

	} else if strings.Contains(fromAddr, "jemin.jeon") {
		// jemin.jeon format
		originalURL := strings.TrimSpace(common.GetNonEmptyLineAfter(bodyLower, "at:"))

		locationStartLine := common.GetNonEmptyLineAfter(bodyLower, "new host link can be aquired from site below")
		if idx := strings.Index(locationStartLine, ","); idx >= 0 {
			locationStartLine = locationStartLine[:idx]
		}
		locationStartLine = strings.TrimSpace(locationStartLine)

		evts, err = parseEvents(serializedEmail, originalURL, locationStartLine, "")
		if err != nil {
			return nil, err
		}

	} else {
		return nil, common.NewParserError("no recognized format found")
	}

	return evts, nil
}

// parseEvents creates events from URLs found after the location start line
func parseEvents(serializedEmail *email.SerializedEmail, originalURL, locationStartLine, copyrightOwner string) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	bodyLower := strings.ToLower(body)

	// Check if original URL is a valid HTTP URL
	var officialURL string
	if strings.HasPrefix(originalURL, "http") {
		officialURL = originalURL
	}

	// Create event template
	copyright := events.NewCopyright("", copyrightOwner, "")
	copyright.OfficialURL = officialURL

	// Get date from email headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	// Extract URLs from the body starting at locationStartLine
	var urls []string
	lines := strings.Split(bodyLower, "\n")

	// Find the start index
	startIndex := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == locationStartLine {
			startIndex = i
			break
		}
	}

	if startIndex == -1 {
		return nil, common.NewParserError("location start line not found in body")
	}

	// Collect URLs starting from startIndex
	for i := startIndex; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "http") {
			urls = append(urls, line)
		} else if len(line) > 0 && !strings.HasPrefix(line, "http") {
			// Stop at first non-empty, non-URL line
			break
		}
	}

	// Create events for each URL
	var evts []*events.Event
	for _, url := range urls {
		evt := events.NewEvent("mediastory")
		evt.URL = url
		evt.EventDate = eventDate
		evt.EventTypes = []events.EventType{copyright}
		evts = append(evts, evt)
	}

	return evts, nil
}

// checkStringMatch checks if any element in the list is contained in the string
func checkStringMatch(list []string, str string) bool {
	for _, el := range list {
		if strings.Contains(str, el) {
			return true
		}
	}
	return false
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
