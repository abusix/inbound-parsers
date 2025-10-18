package centurylink

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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)

	// Check if this is a botnet attack report
	if !strings.Contains(subjectLower, "botnet") {
		return nil, &common.NewTypeError{Subject: subject}
	}

	return parseBotnetAttack(body)
}

func parseBotnetAttack(body string) ([]*events.Event, error) {
	// Remove brackets for IP extraction
	cleanBody := strings.ReplaceAll(body, "[", "")
	cleanBody = strings.ReplaceAll(cleanBody, "]", "")

	// Extract IP address
	ip := common.ExtractOneIP(cleanBody)
	if ip == "" {
		return nil, &common.ParserError{Message: "no IP address found"}
	}

	// Extract date using regex
	dateRegex := regexp.MustCompile(`Date:(.*)`)
	dateMatches := dateRegex.FindAllStringSubmatch(body, -1)
	if len(dateMatches) == 0 {
		return nil, &common.ParserError{Message: "no date found"}
	}

	// Get the last match (Python uses [-1])
	dateStr := strings.TrimSpace(dateMatches[len(dateMatches)-1][1])

	// Extract malware family name
	malwareFamily := common.FindStringWithoutMarkers(body, "Malware Family: ", "")
	if malwareFamily == "" {
		return nil, &common.ParserError{Message: "no malware family found"}
	}

	// Create event
	event := events.NewEvent("centurylink")
	event.IP = ip
	event.EventDate = email.ParseDate(dateStr)
	event.EventTypes = []events.EventType{events.NewMalware(malwareFamily)}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
