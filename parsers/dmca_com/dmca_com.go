package dmca_com

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

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get body with error if empty
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Strip HTML tags from body (equivalent to BeautifulSoup.text)
	body = stripHTML(body)

	// Create event
	event := events.NewEvent("dmca_com")

	// Extract IP address
	event.IP = common.FindStringWithoutMarkers(body, "Infringers IP Address:", "\n")
	event.IP = strings.TrimSpace(event.IP)

	// Set event date from email headers
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Extract URL
	event.URL = common.FindStringWithoutMarkers(body, "Infringing URL:", "\n")
	event.URL = strings.TrimSpace(event.URL)

	// Extract copyright information
	copyrightOwner := common.FindStringWithoutMarkers(body, "authorized agent for", "[")
	copyrightOwner = strings.TrimSpace(copyrightOwner)

	officialURL := common.FindStringWithoutMarkers(body, "Infringed Work:", "\n")
	officialURL = strings.TrimSpace(officialURL)

	protocol := common.FindStringWithoutMarkers(body, "Protocol:", "\n")
	protocol = strings.TrimSpace(protocol)

	// Create Copyright event type with extracted information
	copyright := events.NewCopyright("", copyrightOwner, protocol)
	copyright.OfficialURL = officialURL
	event.EventTypes = []events.EventType{copyright}

	// Extract and add external case ID
	externalID := common.FindStringWithoutMarkers(body, "Notice ID: DMCA-CASE#", "\n")
	externalID = strings.TrimSpace(externalID)
	if externalID != "" {
		event.AddEventDetail(&events.ExternalID{ID: externalID})
	}

	// Add transport protocol as event detail
	if protocol != "" {
		event.AddEventDetail(&events.TransportProtocol{Protocol: protocol})
	}

	return []*events.Event{event}, nil
}

// stripHTML removes HTML tags from a string (equivalent to BeautifulSoup.text)
func stripHTML(html string) string {
	// Replace common block-level tags with newlines
	html = regexp.MustCompile(`(?i)<br[^>]*>`).ReplaceAllString(html, "\n")
	html = regexp.MustCompile(`(?i)<div[^>]*>`).ReplaceAllString(html, "\n")
	html = regexp.MustCompile(`(?i)<p[^>]*>`).ReplaceAllString(html, "\n")

	// Remove all other HTML tags
	html = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(html, "")

	return html
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
