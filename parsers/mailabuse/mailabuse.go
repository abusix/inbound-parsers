package mailabuse

import (
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
	marker := "RBL --"
	var body string

	// Find the part containing the marker
	for _, part := range serializedEmail.Parts {
		partBody := ""
		switch b := part.Body.(type) {
		case string:
			partBody = b
		case []byte:
			partBody = string(b)
		default:
			continue
		}

		if strings.Contains(partBody, marker) {
			body = partBody
			break
		}
	}

	if body == "" {
		return nil, nil
	}

	return appendEvents(marker, body), nil
}

func appendEvents(marker, body string) []*events.Event {
	var eventsList []*events.Event

	// Extract IPs section
	startIndex := strings.Index(body, marker)
	if startIndex == -1 {
		return nil
	}
	startIndex += len(marker)

	endMarker := "-- End"
	endIndex := strings.Index(body[startIndex:], endMarker)
	if endIndex == -1 {
		return nil
	}
	endIndex += startIndex

	// Extract and parse IPs
	ipsSection := body[startIndex:endIndex]
	lines := strings.Split(strings.TrimSpace(ipsSection), "\n")

	// Build a set of IPs using a map
	ipsMap := make(map[string]bool)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		ip := common.IsIP(line)
		if ip != "" {
			ipsMap[ip] = true
		}
	}

	// Find the sample section
	sampleMarker := "-- Example"
	startSample := strings.Index(body[endIndex:], sampleMarker)
	if startSample == -1 {
		// No sample section, create events for all IPs with current time
		currentTime := time.Now().UTC()
		for ip := range ipsMap {
			event := createEvent(ip, &currentTime)
			eventsList = append(eventsList, event)
		}
		return eventsList
	}
	startSample += endIndex + len(sampleMarker)

	endSample := strings.Index(body[startSample:], endMarker)
	if endSample == -1 {
		// No end marker for sample, create events for all IPs with current time
		currentTime := time.Now().UTC()
		for ip := range ipsMap {
			event := createEvent(ip, &currentTime)
			eventsList = append(eventsList, event)
		}
		return eventsList
	}
	endSample += startSample

	// Parse the sample section
	sample := strings.TrimSpace(body[startSample:endSample])
	sampleLines := strings.Split(sample, "\n")

	// Process sample lines to find Received headers
	for i, line := range sampleLines {
		if strings.HasPrefix(strings.TrimSpace(line), "Received:") {
			ip := common.IsIP(common.ExtractOneIP(line))
			if ip == "" {
				continue
			}

			// Check if this IP is in our set
			if ipsMap[ip] {
				// Get the date from the next line
				var eventDate *time.Time
				if i+1 < len(sampleLines) {
					dateStr := strings.TrimSpace(sampleLines[i+1])
					eventDate = email.ParseDate(dateStr)
				}

				// Create event with date
				event := createEvent(ip, eventDate)
				eventsList = append(eventsList, event)

				// Remove IP from map so we don't create duplicate events
				delete(ipsMap, ip)
			}
		}
	}

	// Create events for remaining IPs with current time
	currentTime := time.Now().UTC()
	for ip := range ipsMap {
		event := createEvent(ip, &currentTime)
		eventsList = append(eventsList, event)
	}

	return eventsList
}

func createEvent(ip string, eventDate *time.Time) *events.Event {
	event := events.NewEvent("mailabuse")
	event.IP = ip
	event.EventTypes = []events.EventType{events.NewSpam()}
	event.EventDate = eventDate
	return event
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
