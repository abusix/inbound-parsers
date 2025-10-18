package cert_ua

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

// New creates a new parser instance (wrapper for Bento integration)
func New(se email.SerializedEmail, fa, fn, ct string) *Parser {
	// Ignore the parameters - they're not needed for this parser
	_ = se
	_ = fa
	_ = fn
	_ = ct
	return NewParser()
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	event := events.NewEvent("cert_ua")

	// Extract external ID from subject if present
	idPattern := regexp.MustCompile(`(?i)cert-ua#(\S+)]`)
	if matches := idPattern.FindStringSubmatch(subject); len(matches) > 1 {
		event.AddEventDetail(&events.ExternalID{ID: matches[1]})
	}

	// Route to appropriate parser based on subject/body content
	if regexp.MustCompile(`(?i)malware`).MatchString(subject) {
		return parseMalware(serializedEmail, body, event)
	} else if regexp.MustCompile(`(?i)ddos-attacks`).MatchString(body) {
		return parseDDoS(serializedEmail, subject, event)
	} else if regexp.MustCompile(`(?i)phishing`).MatchString(body) {
		return parsePhishing(serializedEmail, body, event)
	}

	return nil, common.NewNewTypeError(subject)
}

// parseMalware parses malware reports from CSV attachments
func parseMalware(serializedEmail *email.SerializedEmail, body string, eventTemplate *events.Event) ([]*events.Event, error) {
	attachment, err := common.FindFirstAttachmentWithMimeType(serializedEmail, "csv")
	if err != nil {
		return nil, err
	}

	entries, err := common.ParseCSVString(attachment)
	if err != nil {
		return nil, err
	}

	var result []*events.Event
	for _, entry := range entries {
		event := *eventTemplate // Copy the template
		event.EventDetails = append([]events.EventDetail{}, eventTemplate.EventDetails...)

		// Set malware event type
		malwareName := entry["malware"]
		event.EventTypes = []events.EventType{events.NewMalware(malwareName)}

		// Add ASN
		if asn, ok := entry["asn"]; ok && asn != "" {
			event.AddEventDetail(&events.ASN{ASN: asn})
		}

		// Set source port
		if srcPort, ok := entry["src_port"]; ok && srcPort != "" {
			if port, err := common.ParsePort(srcPort); err == nil {
				event.Port = port
			}
		}

		// Add target information
		if dstIP, ok := entry["dst_ip"]; ok && dstIP != "" {
			target := &events.Target{IP: dstIP}
			if dstPort, ok := entry["dst_port"]; ok && dstPort != "" {
				target.Port = dstPort
			}
			event.AddEventDetail(target)
		}

		// Set source IP
		if ip, ok := entry["ip"]; ok && ip != "" {
			event.IP = ip
		}

		// Set event date
		if timestamp, ok := entry["timestamp"]; ok && timestamp != "" {
			if eventDate := email.ParseDate(timestamp); eventDate != nil {
				event.EventDate = eventDate
			}
		}

		result = append(result, &event)
	}

	return result, nil
}

// parsePhishing parses phishing reports
func parsePhishing(serializedEmail *email.SerializedEmail, body string, eventTemplate *events.Event) ([]*events.Event, error) {
	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		if eventDate := email.ParseDate(dateHeaders[0]); eventDate != nil {
			eventTemplate.EventDate = eventDate
		}
	}

	eventTemplate.EventTypes = []events.EventType{events.NewPhishing()}

	// Try to extract IP
	ipPattern := regexp.MustCompile(`(?i)ip:\s*(\S+)`)
	if matches := ipPattern.FindStringSubmatch(body); len(matches) > 1 {
		ip := strings.ReplaceAll(matches[1], "[", "")
		ip = strings.ReplaceAll(ip, "]", "")
		eventTemplate.IP = ip
	}

	var result []*events.Event

	// Try to get URL from "url:" line
	url := common.CleanURL(common.GetNonEmptyLineAfter(body, "url:"))
	if url != "" {
		// Remove square brackets if present
		if strings.HasPrefix(url, "[") && strings.HasSuffix(url, "]") {
			url = url[1 : len(url)-1]
		}
		if common.IsURL(url) {
			url = strings.ReplaceAll(url, "[", "")
			url = strings.ReplaceAll(url, "]", "")
			eventTemplate.URL = url
			event := *eventTemplate
			event.EventDetails = append([]events.EventDetail{}, eventTemplate.EventDetails...)
			result = append(result, &event)
			return result, nil
		}
	}

	// Try to match URL with regex
	urlPattern := regexp.MustCompile(`(?i)url:.*((http|hxxp)\S+)`)
	if matches := urlPattern.FindStringSubmatch(body); len(matches) > 1 {
		eventTemplate.URL = common.CleanURL(matches[1])
		event := *eventTemplate
		event.EventDetails = append([]events.EventDetail{}, eventTemplate.EventDetails...)
		result = append(result, &event)
		return result, nil
	}

	// Check for DNSDB output format
	if strings.Contains(body, "DNSDB output") {
		dnsdbPattern := regexp.MustCompile(`\[(\S+)\']\s+\S+\s*\S+\s*(\S+)\s+(\S+)\s+\S+\s+\S+\s+(\S+)`)
		matches := dnsdbPattern.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) > 4 {
				event := *eventTemplate
				event.EventDetails = append([]events.EventDetail{}, eventTemplate.EventDetails...)

				// Parse date and time
				dateStr := match[2] + " " + match[3]
				if eventDate := email.ParseDate(dateStr); eventDate != nil {
					event.EventDate = eventDate
				}

				// Clean URL
				url := match[4]
				if strings.HasSuffix(url, "|") {
					url = url[:len(url)-1]
				}
				event.URL = url
				event.IP = match[1]
				result = append(result, &event)
			}
		}
		if len(result) > 0 {
			return result, nil
		}
	}

	// Try to extract URLs from URL block
	bodyWithNewline := strings.ReplaceAll(body, "URL:", "URL\n")
	urlBlock := common.GetBlockAfterWithStop(bodyWithNewline, "URL", "")
	for _, line := range urlBlock {
		url := common.CleanURL(line)
		if common.IsURL(url) {
			event := *eventTemplate
			event.EventDetails = append([]events.EventDetail{}, eventTemplate.EventDetails...)
			event.URL = url
			result = append(result, &event)
		}
	}

	if len(result) > 0 {
		return result, nil
	}

	// If we have the base event with just phishing type, return it
	if eventTemplate.IP != "" || eventTemplate.URL != "" {
		event := *eventTemplate
		event.EventDetails = append([]events.EventDetail{}, eventTemplate.EventDetails...)
		return []*events.Event{&event}, nil
	}

	return nil, common.NewParserError("no phishing URLs found")
}

// parseDDoS parses DDoS attack reports
func parseDDoS(serializedEmail *email.SerializedEmail, subject string, event *events.Event) ([]*events.Event, error) {
	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		if eventDate := email.ParseDate(dateHeaders[0]); eventDate != nil {
			event.EventDate = eventDate
		}
	}

	event.EventTypes = []events.EventType{events.NewDDoS()}

	// Extract URL from subject between "Web-site" and "infected with"
	url := common.FindStringWithoutMarkers(subject, "Web-site", "infected with")
	url = strings.TrimSpace(url)
	event.URL = common.CleanURL(url)

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
