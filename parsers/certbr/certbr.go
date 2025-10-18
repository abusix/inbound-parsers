package certbr

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	datePattern      = regexp.MustCompile(`\[(.+)\]`)
	otherDatePattern = regexp.MustCompile(`(?P<month>\w{3})\s(?P<day>\d{2})\s(?P<time>\d\d:\d\d:\d\d)`)
)

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	body = common.RemoveCarriageReturn(body)
	body = strings.TrimSpace(body)

	return getEvents(serializedEmail, body)
}

// parsePhishingSites parses phishing site events
func parsePhishingSites(date *time.Time, body string) ([]*events.Event, error) {
	asnStr := strings.TrimSpace(common.FindStringWithoutMarkers(body, "AS ", "  "))
	data := strings.Trim(common.FindStringWithoutMarkers(body, "# -", "# -"), "- \n\r")

	var eventsList []*events.Event

	for _, line := range strings.Split(data, "\n") {
		split := strings.Fields(line)
		if len(split) < 2 {
			continue
		}

		url := strings.TrimSpace(split[len(split)-1])
		ip := split[len(split)-2]

		event := events.NewEvent("certbr")
		event.EventDate = date
		event.EventTypes = []events.EventType{events.NewPhishing()}
		event.IP = ip
		event.URL = url
		event.AddEventDetail(&events.ASN{ASN: asnStr})

		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

// parsePortmap parses portmap/mdns/dnsmasq events from ZIP attachments
func parsePortmap(subject string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	fullAlertID := common.FindStringWithoutMarkers(subject, "[", "]")
	alertParts := strings.Fields(fullAlertID)
	if len(alertParts) == 0 {
		return nil, common.NewParserError("could not extract alert number from subject")
	}
	alertNumber := alertParts[len(alertParts)-1]

	// Get attachment
	if len(serializedEmail.Parts) == 0 {
		return nil, common.NewParserError("attachment not found")
	}

	attachmentPart := serializedEmail.Parts[len(serializedEmail.Parts)-1]
	var attachmentBytes []byte

	switch body := attachmentPart.Body.(type) {
	case string:
		attachmentBytes = []byte(body)
	case []byte:
		attachmentBytes = body
	default:
		return nil, common.NewParserError("attachment not found")
	}

	// Read ZIP file
	zipReader, err := zip.NewReader(bytes.NewReader(attachmentBytes), int64(len(attachmentBytes)))
	if err != nil {
		return nil, common.NewParserError("failed to read ZIP attachment")
	}

	// Find file in ZIP
	var attachmentData string
	fileName := alertNumber + ".txt"
	found := false

	for _, f := range zipReader.File {
		if f.Name == fileName {
			rc, err := f.Open()
			if err != nil {
				return nil, common.NewParserError("could not open file in ZIP")
			}
			defer rc.Close()

			content, err := io.ReadAll(rc)
			if err != nil {
				return nil, common.NewParserError("could not read file from ZIP")
			}

			attachmentData = string(content)
			found = true
			break
		}
	}

	if !found {
		return nil, common.NewParserError("could not find correct file in attached zip")
	}

	var eventsList []*events.Event

	for _, line := range strings.Split(attachmentData, "\n") {
		parts := strings.Split(line, "|")
		if len(parts) < 5 {
			continue
		}

		var ip, asn, mainType, dateTime, information string
		var port *int

		if len(parts) == 5 {
			ip = parts[0]
			asn = parts[1]
			mainType = parts[2]
			dateTime = parts[3]
			information = parts[4]
		} else if len(parts) == 6 {
			ip = parts[0]
			asn = parts[1]
			portStr := parts[2]
			if portNum, err := common.ParsePort(portStr); err == nil {
				port = &portNum
			}
			mainType = parts[3]
			dateTime = parts[4]
			information = parts[5]
		} else {
			continue
		}

		event := events.NewEvent("certbr")
		event.IP = ip
		if port != nil {
			event.Port = *port
		}
		event.AddEventDetail(&events.ASN{ASN: strings.TrimSpace(asn)})
		event.EventDate = parseMagicDateTime(dateTime)

		mainTypeLower := strings.ToLower(mainType)
		subjectLower := strings.ToLower(subject)

		if strings.Contains(mainTypeLower, "open") {
			var service string
			if strings.Contains(subjectLower, "mikrotik") {
				service = "mikrotik"
			} else if strings.Contains(subjectLower, "mdns") {
				service = "mdns"
			} else if strings.Contains(subjectLower, "portmap") {
				service = "portmap"
			} else {
				return nil, common.NewNewTypeError(subject)
			}
			event.EventTypes = []events.EventType{events.NewOpen(service)}
		} else if strings.Contains(information, "dnsmasq") {
			// Extract version
			infoParts := strings.Split(information, "-")
			version := ""
			if len(infoParts) > 1 {
				version = infoParts[1]
			}
			openEvent := events.NewOpen("dnsmasq")
			// Store version in service field if needed
			if version != "" {
				openEvent.Service = "dnsmasq-" + version
			}
			event.EventTypes = []events.EventType{openEvent}
		} else {
			return nil, common.NewNewTypeError(mainType)
		}

		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

// getSpecificDate extracts date from a log line
func getSpecificDate(line string, mailYear int) *time.Time {
	// Try first pattern [date]
	match := datePattern.FindStringSubmatch(line)
	if match != nil && len(match) > 1 {
		dateString := match[1]
		return parseMagicDateTime(dateString)
	}

	// Try second pattern (MMM DD HH:mm:ss)
	match = otherDatePattern.FindStringSubmatch(line)
	if match != nil {
		month := match[1]
		day := match[2]
		timeStr := match[3]
		year := strconv.Itoa(mailYear)

		dateStr := fmt.Sprintf("%s %s %s %s", month, day, year, timeStr)
		t := parseMagicDateTime(dateStr)
		if t != nil {
			// Check if date is in future
			if t.After(time.Now()) {
				// Try previous year
				year = strconv.Itoa(mailYear - 1)
				dateStr = fmt.Sprintf("%s %s %s %s", month, day, year, timeStr)
				return parseMagicDateTime(dateStr)
			}
		}
		return t
	}

	return nil
}

// getEventsForRawBody parses compromised machine events
func getEventsForRawBody(bodyRaw string) ([]*events.Event, error) {
	var eventsList []*events.Event

	for _, line := range strings.Split(bodyRaw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "--") {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) < 4 {
			continue
		}

		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}

		dateStr := fields[0]
		ipStr := fields[3]

		date := parseMagicDateTime(dateStr)
		ip := common.IsIP(ipStr)

		if ip != "" && date != nil {
			event := events.NewEvent("certbr")
			event.EventTypes = []events.EventType{events.NewBot("")}
			event.IP = ip
			event.EventDate = date
			eventsList = append(eventsList, event)
		}
	}

	return eventsList, nil
}

// parseFakePage parses fake page events
func parseFakePage(serializedEmail *email.SerializedEmail, body, subject string) (*events.Event, error) {
	event := events.NewEvent("certbr")
	event.EventTypes = []events.EventType{events.NewPhishing()}

	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		event.EventDate = email.ParseDate(dateHeader[0])
	}

	event.IP = common.IsIP(common.ExtractOneIP(subject))

	legitimate := common.FindString(body, "legitimate website is:\n", "\n\n")
	if legitimate != "" {
		parts := strings.Split(legitimate, ":")
		if len(parts) > 1 {
			url := strings.Join(parts[1:], ":")
			url = strings.Trim(url, "\n\r\t ")
			event.AddEventDetail(&events.Target{URL: url})
		}
	}

	return event, nil
}

// getEvents main event parsing logic
func getEvents(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	subjectLines, _ := common.GetSubject(serializedEmail, false)
	subject := strings.ToLower(strings.Join(strings.Fields(subjectLines), " "))

	if strings.Contains(subject, "malicious activity against web server") ||
		strings.Contains(subject, "possible malicious activity") {
		ip := common.IsIP(common.ExtractOneIP(subject))

		var date *time.Time
		if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
			date = email.ParseDate(dateHeader[0])
		}

		var eventsList []*events.Event
		logData := strings.TrimSpace(common.FindStringWithoutMarkers(body, "# begin logs", "# end logs"))

		for _, line := range strings.Split(logData, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			var dateCandidate *time.Time
			if date != nil {
				dateCandidate = getSpecificDate(line, date.Year())
			}

			event := events.NewEvent("certbr")
			if dateCandidate != nil {
				event.EventDate = dateCandidate
			} else {
				event.EventDate = date
			}
			event.EventTypes = []events.EventType{events.NewExploit()}
			event.IP = ip
			eventsList = append(eventsList, event)
		}

		return eventsList, nil

	} else if strings.Contains(body, "we have detected phishing") ||
		strings.Contains(subject, "machine hosting") ||
		strings.Contains(subject, "phishing hosted at") {

		extraCondition := strings.Contains(subject, "machine hosting")
		ip := common.IsIP(common.ExtractOneIP(subject))

		data := strings.Split(common.FindStringWithoutMarkers(body, "# begin logs", "# end logs"), "\n")
		if len(data) == 0 || (len(data) == 1 && data[0] == "") {
			data = []string{common.GetNonEmptyLineAfter(body, "hosted at:")}
		}

		var eventsList []*events.Event
		for _, line := range data {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			if extraCondition {
				if !strings.Contains(strings.ToLower(line), "url:") {
					continue
				} else {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) > 1 {
						line = strings.TrimSpace(parts[1])
					}
				}
			}

			event := events.NewEvent("certbr")
			event.IP = ip
			event.URL = line
			event.EventTypes = []events.EventType{events.NewPhishing()}

			if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
				event.EventDate = email.ParseDate(dateHeader[0])
			}

			eventsList = append(eventsList, event)
		}

		return eventsList, nil

	} else if strings.Contains(subject, "rogue dns server") {
		log := strings.TrimSpace(common.FindStringWithoutMarkers(body, "# begin logs", "# end logs"))
		lines := strings.Split(log, "\n")
		if len(lines) == 0 {
			return nil, common.NewParserError("log format changed")
		}

		firstLine := lines[0]
		var parts []string

		// Check if firstLine contains a newline
		if idx := strings.Index(firstLine, "\n"); idx != -1 {
			parts = strings.Split(firstLine[:idx], " | ")
		} else {
			parts = strings.Split(firstLine, " | ")
		}

		if len(parts) < 5 {
			return nil, common.NewParserError("log format changed")
		}

		timestamp := parts[2]

		var eventsList []*events.Event

		// First event for rogue DNS
		event := events.NewEvent("certbr")
		event.EventTypes = []events.EventType{events.NewRogueDNS()}
		event.IP = common.ExtractOneIP(subject)
		event.EventDate = parseMagicDateTime(timestamp)
		eventsList = append(eventsList, event)

		// Parse all log lines for phishing events
		for _, line := range lines {
			lineParts := strings.Split(line, " | ")
			if len(lineParts) < 5 {
				continue
			}

			timestamp := lineParts[2]
			hijackedDomain := lineParts[3]
			phishingIP := lineParts[4]

			phishEvent := events.NewEvent("certbr")
			phishEvent.EventDate = parseMagicDateTime(timestamp)
			phishingEventType := events.NewPhishing()
			// Store official URL in a custom field - Go doesn't have this field in Phishing
			// We'll add it as an event detail instead
			phishEvent.AddEventDetail(&events.Target{URL: hijackedDomain})
			phishEvent.EventTypes = []events.EventType{phishingEventType}
			phishEvent.IP = phishingIP
			eventsList = append(eventsList, phishEvent)
		}

		return eventsList, nil

	} else if strings.Contains(subject, "compromised machine") {
		if len(serializedEmail.Parts) < 2 {
			return nil, common.NewParserError("expected body part not found")
		}

		var bodyRaw string
		switch body := serializedEmail.Parts[1].Body.(type) {
		case string:
			bodyRaw = body
		case []byte:
			bodyRaw = string(body)
		default:
			return nil, common.NewParserError("unexpected body type")
		}

		return getEventsForRawBody(bodyRaw)

	} else if strings.Contains(subject, "fake page") || strings.Contains(subject, "pagina falsa hospedada em") {
		event, err := parseFakePage(serializedEmail, body, subject)
		if err != nil {
			return nil, err
		}
		return []*events.Event{event}, nil

	} else if strings.Contains(subject, "phishing sites") {
		var date *time.Time
		if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
			date = email.ParseDate(dateHeader[0])
		}
		return parsePhishingSites(date, body)

	} else if strings.Contains(subject, "portmap") ||
		strings.Contains(subject, "mdns") ||
		strings.Contains(subject, "dnsmasq vulneravel") ||
		strings.Contains(subject, "possivelmente comprometido") {
		return parsePortmap(subject, serializedEmail)

	} else {
		return nil, common.NewNewTypeError(subject)
	}
}

// parseMagicDateTime attempts to parse datetime in various formats
func parseMagicDateTime(dateStr string) *time.Time {
	if dateStr == "" {
		return nil
	}

	dateStr = strings.TrimSpace(dateStr)

	// Common formats to try
	formats := []string{
		time.RFC3339,
		time.RFC1123Z,
		time.RFC1123,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02T15:04:05.999999999",
		"Jan 2 2006 15:04:05",
		"Jan 02 2006 15:04:05",
		"2 Jan 2006 15:04:05",
		"02 Jan 2006 15:04:05",
		"Mon Jan 2 15:04:05 2006",
		"Mon Jan 02 15:04:05 2006",
		"2006-01-02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return &t
		}
	}

	// Try email.ParseDate for RFC 5322 formats
	if t := email.ParseDate(dateStr); t != nil {
		return t
	}

	return nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
