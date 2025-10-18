package meadowbrookequine

import (
	"fmt"
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

// getAttachedMailFromBody extracts the attached mail from the body
// Remove everything before the first "Received: from localhost" header
func getAttachedMailFromBody(body string) (string, error) {
	idx := strings.Index(body, "received: from localhost")
	if idx == -1 {
		return "", fmt.Errorf("could not retrieve attached mail")
	}
	mailBody := body[idx:]

	// Remove consecutive newlines
	re := regexp.MustCompile(`(\r\n)+`)
	mailBody = re.ReplaceAllString(mailBody, "\r\n")

	return mailBody, nil
}

// parseEventDateFromAttachedMail extracts the event date from the attached mail's Received header
func parseEventDateFromAttachedMail(mailBody string) (*time.Time, error) {
	// Find the first Received header
	lines := strings.Split(mailBody, "\n")
	var receivedHeader string

	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "received:") {
			receivedHeader = line
			break
		}
	}

	if receivedHeader == "" {
		return nil, fmt.Errorf("could not find Received header")
	}

	// Extract date after semicolon
	parts := strings.Split(receivedHeader, ";")
	if len(parts) < 2 {
		return nil, fmt.Errorf("could not find event_date")
	}

	receivedDateStr := strings.TrimSpace(parts[1])
	receivedDate := email.ParseDate(receivedDateStr)

	if receivedDate == nil {
		return nil, fmt.Errorf("could not parse event_date: %s", receivedDateStr)
	}

	return receivedDate, nil
}

// parseIPFromAttachedMail extracts the IP from the last Received header in the attached mail
func parseIPFromAttachedMail(mailBody string) (string, error) {
	// Find all Received headers
	lines := strings.Split(mailBody, "\n")
	var receivedHeaders []string

	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "received:") {
			receivedHeaders = append(receivedHeaders, line)
		}
	}

	if len(receivedHeaders) == 0 {
		return "", fmt.Errorf("no Received headers found")
	}

	// Get the last Received header
	lastReceived := receivedHeaders[len(receivedHeaders)-1]

	// Extract IP from the header
	ip := common.ExtractOneIP(lastReceived)
	if ip == "" {
		return "", fmt.Errorf("could not find valid ip in Received header")
	}

	validIP := common.IsIP(ip)
	if validIP == "" {
		return "", fmt.Errorf("could not find valid ip. Found ip %s", ip)
	}

	return validIP, nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)

	// Get attached mail from body
	mailBody, err := getAttachedMailFromBody(bodyLower)
	if err != nil {
		return nil, err
	}

	event := events.NewEvent("meadowbrookequine")

	// Set event types based on body content
	var eventTypes []events.EventType
	if strings.Contains(bodyLower, "phishing") {
		eventTypes = append(eventTypes, events.NewPhishing())
	}
	if strings.Contains(bodyLower, "spam") {
		eventTypes = append(eventTypes, events.NewSpam())
	}
	event.EventTypes = eventTypes

	// Try to find IP in the body first (originating line)
	var ip string
	for _, line := range strings.Split(bodyLower, "\n") {
		if strings.Contains(line, "originating") {
			ip = common.ExtractOneIP(line)
			break
		}
	}

	// If no IP found in body, parse it from attached mail
	if ip == "" {
		ip, err = parseIPFromAttachedMail(mailBody)
		if err != nil {
			return nil, err
		}
	}

	// Parse event date from attached mail
	eventDate, err := parseEventDateFromAttachedMail(mailBody)
	if err != nil {
		return nil, err
	}

	event.IP = ip
	event.EventDate = eventDate

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
