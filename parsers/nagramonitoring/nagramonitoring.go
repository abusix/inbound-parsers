package nagramonitoring

import (
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

// stripHTML removes HTML tags from a string (similar to BeautifulSoup text extraction)
func stripHTML(html string) string {
	// Remove script and style tags with their content
	scriptRe := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	html = scriptRe.ReplaceAllString(html, "")
	styleRe := regexp.MustCompile(`(?i)<style[^>]*>.*?</style>`)
	html = styleRe.ReplaceAllString(html, "")

	// Remove all HTML tags
	tagRe := regexp.MustCompile(`<[^>]+>`)
	html = tagRe.ReplaceAllString(html, " ")

	// Normalize whitespace
	wsRe := regexp.MustCompile(`\s+`)
	html = wsRe.ReplaceAllString(html, " ")

	return strings.TrimSpace(html)
}

// getTextLinebreak determines the linebreak style used in the text
func getTextLinebreak(text string) string {
	if strings.Contains(text, "\r\n") {
		return "\r\n"
	}
	return "\n"
}

// parseCopyright parses copyright infringement notifications
func (p *Parser) parseCopyright(body string) ([]*events.Event, error) {
	var result []*events.Event

	// Extract Notice ID
	noticeID := common.FindStringWithoutMarkers(body, "Notice ID: ", "")

	// Extract Match Name (copyrighted work)
	matchName := common.FindStringWithoutMarkers(body, "Match Name :", "")

	// Extract copyright owner
	owner := common.FindStringWithoutMarkers(body, "authorized agent of ", ", hereinafter")
	if owner == "" {
		owner = common.GetNonEmptyLineAfter(body, "\"Rightsholders\"")
	}

	// Extract IP address
	ip := common.GetNonEmptyLineAfter(body, "Server IP Address:")

	// Extract URLs
	linebreak := getTextLinebreak(body)
	urlsText := common.FindStringWithoutMarkers(body, "URL:", linebreak+linebreak)
	urlsText = strings.TrimSpace(urlsText)

	var urls []string
	if urlsText != "" {
		// Split by newlines and filter empty lines
		lines := strings.Split(urlsText, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				urls = append(urls, line)
			}
		}
	}

	// If no URLs found in URL: section, try Protected Content:
	if len(urls) == 0 {
		urls = common.GetBlockAfterWithStop(body, "Protected Content:", "")
	}

	// Extract notice date
	noticeDate := common.FindStringWithoutMarkers(body, "Notice Date: ", "")

	// Create events for each URL
	for _, urlLine := range urls {
		event := events.NewEvent("nagramonitoring")

		// Set copyright information
		copyright := events.NewCopyright(matchName, owner, "")
		event.EventTypes = []events.EventType{copyright}

		// Add external ID if we have a notice ID
		if noticeID != "" {
			event.AddEventDetail(&events.ExternalID{ID: noticeID})
		}

		// Parse URL and date from line
		// Format can be either:
		// 1. "url found on date" (when notice date is prepended)
		// 2. Just "url" (when URLs are from Protected Content block)

		var url string
		var dateStr string

		if strings.Contains(urlLine, "found on") {
			parts := strings.SplitN(urlLine, "found on", 2)
			url = strings.TrimSpace(parts[0])
			if len(parts) > 1 {
				dateStr = strings.TrimSpace(parts[1])
			}
		} else {
			url = strings.TrimSpace(urlLine)
			dateStr = noticeDate
		}

		// Clean the URL
		url = common.CleanURL(url)
		event.URL = url

		// Parse and set event date
		if dateStr != "" {
			event.EventDate = email.ParseDate(dateStr)
		}

		// Add IP if available
		if ip != "" {
			event.IP = ip
		}

		result = append(result, event)
	}

	return result, nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get email body
	rawBody, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Strip HTML to get plain text
	body := stripHTML(rawBody)

	// Get subject
	subject, _ := common.GetSubject(serializedEmail, false)

	// Check if this is an infringement notification
	if strings.Contains(subject, "Infringement notification") {
		return p.parseCopyright(body)
	}

	// Unknown email type
	return nil, common.NewParserError("unknown email type: " + subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
