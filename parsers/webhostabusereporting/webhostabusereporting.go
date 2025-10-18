package webhostabusereporting

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

// New creates a new Parser instance (for Bento registration)
func New(serializedEmail email.SerializedEmail, fromAddr, fromName, contentType string) *Parser {
	return &Parser{}
}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Check if from address matches
	fromAddr, _ := common.GetFrom(serializedEmail, false)
	if fromAddr != "alerts@webhostabusereporting.com" {
		return nil, nil
	}

	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	trademarkOwner := ""
	var registrationNumbers []string
	ip := ""

	// Extract trademark owner, registration numbers, and IP
	for _, line := range strings.Split(body, "\n") {
		lineLower := strings.ToLower(line)

		// Extract trademark owner
		if strings.Contains(lineLower, "trademark owner") && trademarkOwner == "" {
			idx := strings.Index(lineLower, "trademark owner")
			prefixLen := len("trademark owner") + 2 // e.g. trademark owner - eurobet
			if idx+prefixLen < len(line) {
				trademarkOwner = strings.TrimSpace(line[idx+prefixLen:])
			}
		}

		// Extract trademark name as alternative to owner
		if strings.Contains(lineLower, "trademark name") && trademarkOwner == "" {
			idx := strings.Index(lineLower, "trademark name")
			prefixLen := len("trademark name") + 2 // e.g. Trademark Name: HYDRO QUEBEC
			if idx+prefixLen < len(line) {
				trademarkOwner = strings.TrimSpace(line[idx+prefixLen:])
			}
		}

		// Extract registration number
		if strings.Contains(lineLower, "registration number") && len(registrationNumbers) == 0 {
			idx := strings.Index(lineLower, "registration number")
			prefixLen := len("registration number") + 2 // e.g. Registration number - 20...
			if idx+prefixLen < len(line) {
				candidate := strings.TrimSpace(line[idx+prefixLen:])
				if !strings.Contains(candidate, " ") {
					registrationNumbers = append(registrationNumbers, candidate)
				}
			}
		}

		// Extract IP address
		if strings.Contains(lineLower, "ip address") && ip == "" {
			ip = common.ExtractOneIP(line)
		}
	}

	// Try alternative methods to find trademark owner if not found yet
	possibleDelimiters := []string{"and ", "they ", "."}
	for _, delimiter := range possibleDelimiters {
		if trademarkOwner != "" && !strings.Contains(trademarkOwner, "\n") {
			break
		}
		trademarkOwner = strings.TrimSpace(
			common.FindStringWithoutMarkers(body, "authorized representatives of", delimiter),
		)
	}

	// Create event
	event := events.NewEvent("webhostabusereporting")

	// Set event date from email headers
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			if eventDate := email.ParseDate(dateHeaders[0]); eventDate != nil {
				event.EventDate = eventDate
			}
		}
	}

	// Set IP
	event.IP = ip

	// Determine event type
	bodyLower := strings.ToLower(body)
	if strings.Contains(bodyLower, "phishing") && !strings.Contains(bodyLower, "trademark") {
		event.EventTypes = []events.EventType{events.NewPhishing()}
	} else {
		event.EventTypes = []events.EventType{
			events.NewTrademark("", registrationNumbers, trademarkOwner, ""),
		}
	}

	// Find URL from the body
	possibleURLBlockDelimiters := []string{
		"you are the host",
		"hosted by you",
		"below-mentioned domain",
		"hosted on your",
		"brought the following",
		"representatives of",
		"to our attention",
	}

	// Find which delimiter exists in the body
	var urlBlockDelimiter string
	for _, delimiter := range possibleURLBlockDelimiters {
		if strings.Contains(body, delimiter) {
			urlBlockDelimiter = delimiter
			break
		}
	}

	// Extract URL from the block after the delimiter
	if urlBlockDelimiter != "" {
		lines := common.GetBlockAfterWithStop(body, urlBlockDelimiter, "")
		for _, line := range lines {
			lineLower := strings.ToLower(line)
			if strings.Contains(lineLower, "ip address") && !strings.Contains(line, "http") {
				continue
			}

			// Try to process as URL
			if processedURL, err := common.ProcessURL(line); err == nil {
				event.URL = processedURL
				break
			}
		}
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
