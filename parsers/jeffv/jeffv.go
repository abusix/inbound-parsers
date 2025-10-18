package jeffv

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

var (
	headerKey          = `[\w-]+:`
	looksLikeHeaderRe  = regexp.MustCompile(`(?m)(?s)^Received(.*?)(?=` + headerKey + `)`)
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

	trimmedBody := strings.TrimSpace(body)
	if !strings.HasPrefix(trimmedBody, "spam") {
		lines := strings.Split(trimmedBody, "\n")
		firstLine := ""
		if len(lines) > 0 {
			firstLine = strings.TrimSpace(lines[0])
		}
		return nil, common.NewNewTypeError(firstLine)
	}

	event := events.NewEvent("jeffv")
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Extract spam mail after forwarded message marker
	parts := strings.Split(body, "-------- Forwarded Message --------")
	if len(parts) == 0 {
		return nil, common.NewParserError("Could not find forwarded message")
	}
	spamMail := strings.TrimSpace(parts[len(parts)-1])

	// Extract received header using regex
	matches := looksLikeHeaderRe.FindStringSubmatch(spamMail)
	if len(matches) < 2 {
		return nil, common.NewParserError("Could not extract received headers")
	}

	receivedHeader := strings.TrimSpace(matches[1])

	// Split on semicolon to separate IP from date
	semicolonIdx := strings.Index(receivedHeader, "; ")
	if semicolonIdx == -1 {
		return nil, common.NewParserError("Could not parse received header format")
	}

	firstPart := receivedHeader[:semicolonIdx]
	dateStr := strings.TrimSpace(receivedHeader[semicolonIdx+2:])

	// Set event date
	if dateStr != "" {
		eventDate := email.ParseDate(dateStr)
		event.EventDate = eventDate
	}

	// Set IP from first part
	if validIP := common.IsIP(firstPart); validIP != "" {
		event.IP = validIP
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
