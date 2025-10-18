package inaxas

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

var (
	targetRegex = regexp.MustCompile(`target server public ip(?P<ip>\S+)target server sip port(?P<port>\d+)`)
	sourceRegex = regexp.MustCompile(`from the ip address(?P<ip>.*)`)
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

	// Strip HTML tags to get plain text (similar to BeautifulSoup.text)
	bodyLower := strings.ToLower(stripHTMLTags(body))

	if !strings.Contains(bodyLower, "unauthorized dial attempt") {
		return nil, &common.NewTypeError{Subject: getIdentifier(serializedEmail)}
	}

	event := events.NewEvent("inaxas")
	event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

	// Extract and parse event date
	dateString := common.FindStringWithoutMarkers(
		bodyLower,
		"sip servers monitored by our service at",
		".",
	)
	dateString = strings.TrimSpace(dateString)

	if dateString != "" {
		// Parse date format: "Monday, 01 January 2024 12:00:00"
		// Python format: '%A, %d %B %Y %X'
		layouts := []string{
			"Monday, 02 January 2006 15:04:05",
			"Monday, 2 January 2006 15:04:05",
		}

		for _, layout := range layouts {
			if parsedDate, err := time.Parse(layout, dateString); err == nil {
				event.EventDate = &parsedDate
				break
			}
		}
	}

	// Extract target IP and port
	if match := targetRegex.FindStringSubmatch(bodyLower); match != nil {
		targetIP := match[1]
		targetPortStr := match[2]

		event.AddEventDetail(&events.Target{
			IP:   targetIP,
			Port: targetPortStr,
		})
	}

	// Extract source IP
	if match := sourceRegex.FindStringSubmatch(bodyLower); match != nil {
		sourceIP := strings.TrimSpace(match[1])
		event.IP = sourceIP

		// Only yield event if we found source IP
		return []*events.Event{event}, nil
	}

	// If no source IP found, don't return the event
	return nil, nil
}

// stripHTMLTags removes HTML tags from a string
func stripHTMLTags(html string) string {
	tagRegex := regexp.MustCompile(`<[^>]+>`)
	return tagRegex.ReplaceAllString(html, " ")
}

// getIdentifier safely extracts the identifier from serialized email
func getIdentifier(serializedEmail *email.SerializedEmail) string {
	if serializedEmail.Headers != nil {
		if msgID, ok := serializedEmail.Headers["message-id"]; ok && len(msgID) > 0 {
			return msgID[0]
		}
	}
	return "unknown"
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
