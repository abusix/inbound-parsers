package zap_hosting

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the zap_hosting parser
type Parser struct{}

// NewParser creates a new zap_hosting parser
func NewParser() *Parser {
	return &Parser{}
}

// Match returns true if the email should be parsed by this parser
// Matches emails from @zap-hosting, but rejects ticket responses
func Match(serializedEmail *email.SerializedEmail, fromAddr string) bool {
	if fromAddr == "" || !strings.Contains(fromAddr, "@zap-hosting") {
		return false
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return false
	}

	subjectLower := strings.ToLower(subject)
	if strings.Contains(subjectLower, "answered") || strings.Contains(subjectLower, "your ticket has been created") {
		return false
	}

	return true
}

// Parse parses emails from ZAP-Hosting abuse reports
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get email body and subject
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, common.NewParserError("failed to get email body: " + err.Error())
	}
	body = strings.ToLower(body)

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, common.NewParserError("failed to get email subject: " + err.Error())
	}
	subject = strings.ToLower(subject)

	// Strip HTML tags and collapse whitespace
	bodyString := stripHTMLAndCollapseSpaces(body)

	event := events.NewEvent("zap_hosting")

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	// Determine IP source and event type
	var typeString string
	if strings.Contains(bodyString, "new ticket") {
		// Extract IP from body
		event.IP = common.ExtractOneIP(bodyString)

		// Extract external ID (ticket number)
		externalID := findStringWithoutMarkers(bodyString, "id #", " ")
		if externalID != "" {
			event.AddEventDetail(&events.ExternalID{
				ID: externalID,
			})
		}

		typeString = bodyString
	} else {
		// Extract IP from subject
		event.IP = common.ExtractOneIP(subject)
		typeString = subject
	}

	// Determine event type based on content
	if strings.Contains(typeString, "phishing") {
		event.EventTypes = []events.EventType{events.NewPhishing()}
	} else if strings.Contains(typeString, "spam") {
		event.EventTypes = []events.EventType{events.NewSpam()}
	} else if strings.Contains(typeString, "fraud") {
		event.EventTypes = []events.EventType{events.NewFraud()}
	} else if strings.Contains(typeString, "malware") {
		event.EventTypes = []events.EventType{events.NewMalware("")}
	} else {
		return nil, common.NewParserError(fmt.Sprintf("unknown event type in subject: %s", subject))
	}

	return []*events.Event{event}, nil
}

// stripHTMLAndCollapseSpaces removes HTML tags and collapses whitespace
// This mimics the Python BeautifulSoup behavior: ' '.join(list(filter(lambda x: x != ' ', BeautifulSoup(body).strings))).replace('  ', ' ')
func stripHTMLAndCollapseSpaces(html string) string {
	// Remove HTML tags using regex
	tagRegex := regexp.MustCompile(`<[^>]*>`)
	text := tagRegex.ReplaceAllString(html, " ")

	// Decode common HTML entities
	text = strings.ReplaceAll(text, "&nbsp;", " ")
	text = strings.ReplaceAll(text, "&amp;", "&")
	text = strings.ReplaceAll(text, "&lt;", "<")
	text = strings.ReplaceAll(text, "&gt;", ">")
	text = strings.ReplaceAll(text, "&quot;", "\"")
	text = strings.ReplaceAll(text, "&#39;", "'")

	// Split into words and filter out empty strings
	words := strings.Fields(text)

	// Join with single space
	result := strings.Join(words, " ")

	return result
}

// findStringWithoutMarkers finds text between two markers
// This is a local implementation similar to common.FindStringWithoutMarkers
// but specifically for this parser's needs
func findStringWithoutMarkers(text, startMarker, endMarker string) string {
	startIdx := strings.Index(text, startMarker)
	if startIdx == -1 {
		return ""
	}

	startIdx += len(startMarker)
	remaining := text[startIdx:]

	if endMarker == "" {
		return strings.TrimSpace(remaining)
	}

	endIdx := strings.Index(remaining, endMarker)
	if endIdx == -1 {
		return strings.TrimSpace(remaining)
	}

	return strings.TrimSpace(remaining[:endIdx])
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
