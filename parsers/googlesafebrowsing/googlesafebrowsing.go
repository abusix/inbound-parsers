package googlesafebrowsing

import (
	"encoding/xml"
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	// parenthesisMatcher matches lines with parentheses containing digits, e.g., "(123.45.67.89)\n"
	parenthesisMatcher = regexp.MustCompile(`\(\d.*\)\r?\n`)
)

// NotificationMessage represents the XML structure from Google Safe Browsing
type NotificationMessage struct {
	XMLName xml.Name `xml:"notification_message"`
	ASN     string   `xml:"asn,attr"`
	List    struct {
		UrlInfo []UrlInfo `xml:"url_info"`
	} `xml:"list"`
}

// UrlInfo represents a single URL report in the XML
type UrlInfo struct {
	IP  string `xml:"ip,attr"`
	URL string `xml:"url,attr"`
}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Get date from headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	var eventsList []*events.Event

	// Check if body starts with '<' (XML format)
	if strings.HasPrefix(strings.TrimSpace(body), "<") {
		events, err := p.parseXMLFormat(body, eventDate)
		if err != nil {
			return nil, err
		}
		eventsList = append(eventsList, events...)
	} else {
		// Plain text format
		events, err := p.parseTextFormat(body, eventDate)
		if err != nil {
			return nil, err
		}
		eventsList = append(eventsList, events...)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no events extracted from Google Safe Browsing report")
	}

	return eventsList, nil
}

// parseXMLFormat parses the XML format email body
func (p *Parser) parseXMLFormat(body string, eventDate *time.Time) ([]*events.Event, error) {
	var notification NotificationMessage
	if err := xml.Unmarshal([]byte(body), &notification); err != nil {
		return nil, common.NewParserError("failed to parse XML: " + err.Error())
	}

	var eventsList []*events.Event

	for _, urlInfo := range notification.List.UrlInfo {
		event := events.NewEvent("googlesafebrowsing")
		event.EventDate = eventDate

		// Set IP
		if validIP := common.IsIP(urlInfo.IP); validIP != "" {
			event.IP = validIP
		}

		// Set URL
		event.URL = urlInfo.URL

		// Set event type
		phishing := events.NewPhishing()
		phishing.PhishingTarget = urlInfo.URL
		event.EventTypes = []events.EventType{phishing}

		// Add ASN detail if present
		if notification.ASN != "" {
			event.AddEventDetail(&events.ASN{
				ASN: notification.ASN,
			})
		}

		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

// parseTextFormat parses the plain text format email body
func (p *Parser) parseTextFormat(body string, eventDate *time.Time) ([]*events.Event, error) {
	// Find first IP in parentheses
	matches := parenthesisMatcher.FindString(body)
	if matches == "" {
		return nil, common.NewParserError("no IP pattern found in text format")
	}

	firstIP := strings.TrimSpace(matches)

	// Get block around the first IP
	dataBlock := common.GetBlockAround(body, firstIP)
	if len(dataBlock) == 0 {
		return nil, common.NewParserError("no data block found around IP pattern")
	}

	// Join block and remove all whitespace
	dataPart := strings.Join(dataBlock, "")
	dataPart = strings.ReplaceAll(dataPart, " ", "")
	dataPart = strings.ReplaceAll(dataPart, "\t", "")
	dataPart = strings.ReplaceAll(dataPart, "\n", "")
	dataPart = strings.ReplaceAll(dataPart, "\r", "")

	// Parse entries: items map IP -> []URL
	items := make(map[string][]string)

	// Split by closing parenthesis to get individual entries
	parts := strings.Split(dataPart, ")")
	for _, line := range parts {
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Split by opening parenthesis to separate URL from IP
		// Format: url_or_domain(ip
		idx := strings.LastIndex(line, "(")
		if idx == -1 {
			continue
		}

		urlOrDomain := line[:idx]
		ipStr := line[idx+1:]

		// Extract and validate IP
		validIP := common.IsIP(common.ExtractOneIP(ipStr))
		if validIP == "" {
			continue
		}

		// Add to items map
		items[validIP] = append(items[validIP], urlOrDomain)
	}

	// Create events from parsed data
	var eventsList []*events.Event

	for ip, urlList := range items {
		for _, url := range urlList {
			event := events.NewEvent("googlesafebrowsing")
			event.EventDate = eventDate
			event.IP = ip
			event.URL = url

			// Set event type
			phishing := events.NewPhishing()
			phishing.PhishingTarget = url
			event.EventTypes = []events.EventType{phishing}

			eventsList = append(eventsList, event)
		}
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
