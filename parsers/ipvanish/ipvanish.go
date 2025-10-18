package ipvanish

import (
	"fmt"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// getNewHeaderAndBody extracts headers and body from the forwarded ZenDesk message
// This matches the Python _get_new_header_and_body() function
func getNewHeaderAndBody(body string, serializedEmail *email.SerializedEmail) (string, map[string][]string, error) {
	headerDict := make(map[string][]string)

	// Find the body separator line
	newBodyIndex := strings.Index(body, "----------------------------------------------")
	if newBodyIndex == -1 {
		return "", nil, fmt.Errorf("separator line not found in body")
	}
	newBody := body[newBodyIndex:]

	// Parse HTML to find the sender email (mailto link)
	htmlBody, err := common.FindFirstAttachmentWithMimeType(serializedEmail, "html")
	if err != nil {
		return "", nil, fmt.Errorf("html attachment not found: %w", err)
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlBody))
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	// Find all anchor tags and look for mailto links
	var newFromAddr string
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists {
			if strings.Contains(href, "mailto:") {
				newFromAddr = s.Text()
				return
			}
		}
	})

	if newFromAddr == "" {
		return "", nil, fmt.Errorf("no mailto link found in HTML")
	}

	// Extract ticket creator and date
	var dateString string
	ticketCreator := common.FindStringWithoutMarkers(body, "Ticket Creator - ,", ")")
	if ticketCreator != "" {
		// Parse ticket creator name
		parts := strings.Split(ticketCreator, "(")
		if len(parts) > 0 {
			ticketCreatorName := strings.TrimSpace(parts[0])
			dateString = common.FindStringWithoutMarkers(newBody, ticketCreatorName+",", "\n")
		}
	} else {
		// Fallback: use from address to find date
		dateString = common.FindStringWithoutMarkers(newBody, newFromAddr+",", "\n")
	}

	// Extract new subject - remove the ZenDesk prefix
	oldSubject := ""
	if subjectHeaders, ok := serializedEmail.Headers["subject"]; ok && len(subjectHeaders) > 0 {
		oldSubject = subjectHeaders[0]
	}

	// Split by " - " and take everything after the first part
	subjectParts := strings.Split(oldSubject, " - ")
	var newSubject string
	if len(subjectParts) > 1 {
		newSubject = strings.Join(subjectParts[1:], " - ")
	} else {
		newSubject = oldSubject
	}

	// Build new headers
	headerDict["from"] = []string{newFromAddr}
	headerDict["subject"] = []string{newSubject}

	// Parse the forwarded date
	dateString = strings.TrimSpace(dateString)
	parsedDate := parseForwardedDate(dateString, []string{"%b %d, %Y, %I:%M %p"})
	if parsedDate != nil {
		headerDict["date"] = []string{parsedDate.Format(time.RFC1123Z)}
	} else {
		// Fallback to original date
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			headerDict["date"] = []string{dateHeaders[0]}
		}
	}

	// Preserve "to" header
	if toHeaders, ok := serializedEmail.Headers["to"]; ok {
		headerDict["to"] = toHeaders
	}

	return newBody, headerDict, nil
}

// parseForwardedDate parses a date string with Python strftime formats
// This matches the Python get_forwarded_date() function
func parseForwardedDate(dateStr string, formats []string) *time.Time {
	dateStr = strings.TrimSpace(dateStr)
	if dateStr == "" {
		return nil
	}

	// Convert Python strftime formats to Go time formats
	// E.g: "Aug 5, 2022, 2:03 AM" -> "%b %d, %Y, %I:%M %p"
	goFormats := make([]string, len(formats))
	for i, pyFormat := range formats {
		goFormat := pyFormat
		// Python to Go format conversions
		goFormat = strings.ReplaceAll(goFormat, "%b", "Jan")  // Abbreviated month
		goFormat = strings.ReplaceAll(goFormat, "%d", "2")    // Day
		goFormat = strings.ReplaceAll(goFormat, "%Y", "2006") // Year
		goFormat = strings.ReplaceAll(goFormat, "%I", "3")    // Hour (12-hour)
		goFormat = strings.ReplaceAll(goFormat, "%M", "04")   // Minute
		goFormat = strings.ReplaceAll(goFormat, "%p", "PM")   // AM/PM
		goFormats[i] = goFormat
	}

	// Try each format
	for _, format := range goFormats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return &t
		}
	}

	return nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Extract new body and headers
	newBody, newHeaders, err := getNewHeaderAndBody(body, serializedEmail)
	if err != nil {
		return nil, err
	}

	// Modify the serialized email in place (rewrite pattern)
	serializedEmail.Body = newBody
	serializedEmail.Headers = newHeaders

	// Create a simple event - the actual parsing will be done by another parser
	// after this rewrite. This is a pass-through to indicate the email was rewritten.
	event := events.NewEvent("ipvanish")
	event.EventTypes = []events.EventType{events.NewSpam()}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
