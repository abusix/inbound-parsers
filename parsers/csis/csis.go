package csis

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)

	// Extract fields using FindStringWithoutMarkers with newline as end marker
	typeString := strings.TrimSpace(findStringToNewline(bodyLower, "abuse type:"))
	targetBrand := strings.TrimSpace(findStringToNewline(bodyLower, "targeted brand:"))
	dateStr := strings.TrimSpace(findStringToNewline(bodyLower, "abuse reported:"))

	// Extract and clean URL (handle obfuscation)
	url := strings.TrimSpace(findStringToNewline(bodyLower, "obfuscated full url:"))
	url = strings.ReplaceAll(url, " _._ ", "_._")
	url = strings.ReplaceAll(url, "_._", ".")

	// Extract IPs (comma-separated list)
	ipsStr := findStringToNewline(bodyLower, "ipv4(s):")
	ips := strings.Split(ipsStr, ",")

	// Extract ASNs (pipe-separated list)
	asnStr := findStringToNewline(bodyLower, "asn(s):")
	asnParts := strings.Split(asnStr, "|")

	// Extract only digits from ASN values
	asns := make([]string, 0, len(asnParts))
	digitRegex := regexp.MustCompile(`\d+`)
	for _, asnPart := range asnParts {
		digits := digitRegex.FindAllString(asnPart, -1)
		if len(digits) > 0 {
			asns = append(asns, strings.Join(digits, ""))
		}
	}

	// Determine event type
	var eventType events.EventType
	if strings.Contains(typeString, "phishing") {
		eventType = events.NewPhishing()
	} else {
		return nil, common.NewNewTypeError(typeString)
	}

	// Create events by zipping IPs with ASNs
	var evtList []*events.Event

	// Zip IPs and ASNs together
	maxLen := len(ips)
	if len(asns) < maxLen {
		maxLen = len(asns)
	}

	for i := 0; i < maxLen; i++ {
		ip := strings.TrimSpace(ips[i])
		asn := ""
		if i < len(asns) {
			asn = strings.TrimSpace(asns[i])
		}

		evt := events.NewEvent("csis")
		evt.IP = ip
		evt.URL = url
		evt.EventDate = parseCSISDate(dateStr)
		evt.EventTypes = []events.EventType{eventType}

		// Add ASN detail if available
		if asn != "" {
			evt.AddEventDetail(&events.ASN{
				ASN: asn,
			})
		}

		// Add Target brand detail
		if targetBrand != "" {
			evt.AddEventDetail(&events.Target{
				Brand: targetBrand,
			})
		}

		evtList = append(evtList, evt)
	}

	if len(evtList) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return evtList, nil
}

// findStringToNewline finds text after a marker up to the next newline
// This mimics Python's find_string_without_markers with default endswith parameter
func findStringToNewline(text, startMarker string) string {
	idx := strings.Index(text, startMarker)
	if idx == -1 {
		return ""
	}

	// Move past the start marker
	idx += len(startMarker)
	remaining := text[idx:]

	// Find the next newline
	newlineIdx := strings.Index(remaining, "\n")
	if newlineIdx == -1 {
		// No newline found, return rest of string
		return remaining
	}

	return remaining[:newlineIdx]
}

// parseCSISDate parses CSIS date format: "2021-08-27 23:07"
func parseCSISDate(dateStr string) *time.Time {
	if dateStr == "" {
		return nil
	}

	// CSIS uses format: "YYYY-MM-DD HH:MM"
	formats := []string{
		"2006-01-02 15:04",
		"2006-01-02 15:04:05",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return &t
		}
	}

	// Try standard email date parsing as fallback
	return email.ParseDate(dateStr)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
