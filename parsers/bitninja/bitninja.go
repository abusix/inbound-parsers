package bitninja

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
)

var fieldMatcher = regexp.MustCompile(`<pre[^>]*>([\W\w]*?)</pre>`)
var portRegex = regexp.MustCompile(`:(\d+)(?:\D|$)`)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	bodyLower := strings.ToLower(body)

	event := events.NewEvent("bitninja")

	// Extract IP from body
	event.IP = common.FindStringWithoutMarkers(bodyLower, "ip ", " ")

	// If IP not found in plain body, try HTML attachment
	if event.IP == "" {
		htmlBody, err := common.FindFirstAttachmentWithMimeType(serializedEmail, "html")
		if err == nil {
			// Strip HTML tags to get plain text (simplified version of BeautifulSoup)
			bodyLower = stripHTMLTags(strings.ToLower(htmlBody))
			event.IP = common.ExtractOneIP(bodyLower)
		}
	}

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Always add Bot event type
	event.EventTypes = []events.EventType{events.NewBot("")}

	// Find all <pre> blocks and check for spam or port scan indicators
	matches := fieldMatcher.FindAllStringSubmatch(bodyLower, -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		fieldData := match[1]

		// Check for spam trap indicator
		if strings.Contains(fieldData, `"reached trap mailbox"`) {
			event.EventTypes = append(event.EventTypes, events.NewSpam())
			break
		}

		// Check for port scan indicator
		if strings.Contains(fieldData, `"port hit"`) {
			// Try to parse as JSON
			var jsonData map[string]interface{}
			if err := json.Unmarshal([]byte(fieldData), &jsonData); err == nil {
				if portHitData, ok := jsonData["port hit"]; ok {
					portHitStr, ok := portHitData.(string)
					if ok {
						// Extract ports using regex
						ports := portRegex.FindAllStringSubmatch(portHitStr, -1)
						if len(ports) >= 2 {
							// First port is the source port, set as event port
							if port, err := strconv.Atoi(ports[0][1]); err == nil {
								event.Port = port
							}

							// Extract target IP: split by semicolon, take last part, split by colon
							parts := strings.Split(portHitStr, ";")
							if len(parts) > 0 {
								lastPart := strings.TrimSpace(parts[len(parts)-1])
								colonParts := strings.Split(lastPart, ":")
								if len(colonParts) > 0 {
									targetIP := strings.TrimSpace(colonParts[0])

									// Add target detail with IP and second port
									targetPort := ""
									if len(ports) >= 2 {
										targetPort = ports[1][1]
									}
									event.AddEventDetail(&events.Target{
										IP:   targetIP,
										Port: targetPort,
									})
								}
							}

							event.EventTypes = append(event.EventTypes, events.NewPortScan())
						}
					}
				}
			}
			break
		}
	}

	return []*events.Event{event}, nil
}

// stripHTMLTags removes HTML tags from a string (simple implementation)
func stripHTMLTags(html string) string {
	tagRegex := regexp.MustCompile(`<[^>]+>`)
	return tagRegex.ReplaceAllString(html, " ")
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
