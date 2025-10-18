package cpragency

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// stripHTML removes HTML tags from a string (simple implementation)
func stripHTML(html string) string {
	// Remove HTML tags
	re := regexp.MustCompile(`<[^>]*>`)
	text := re.ReplaceAllString(html, " ")
	// Clean up extra whitespace
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")
	return strings.TrimSpace(text)
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	body = stripHTML(body)
	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	var result []*events.Event

	// Check for copyright/copyrigt in subject
	if strings.Contains(subjectLower, "copyright") || strings.Contains(subjectLower, "copyrigt") {
		eventTemplate := events.NewEvent("cpragency")
		eventTemplate.EventTypes = []events.EventType{events.NewCopyright("", "", "")}

		// Set event date
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		}

		// Extract URL
		url := common.FindStringWithoutMarkers(body, "the infringing content below:", "I confirm")
		eventTemplate.URL = url

		// Check for IP addresses
		if strings.Contains(body, "IP addresses:") {
			ipsString := common.FindStringWithoutMarkers(body, "IP addresses:", "This")
			ipsString = strings.TrimSpace(ipsString)
			if len(ipsString) > 0 && strings.HasSuffix(ipsString, ".") {
				ipsString = ipsString[:len(ipsString)-1]
			}
			if ipsString != "" {
				ips := strings.Split(ipsString, ",")
				for _, ip := range ips {
					ipClean := common.IsIP(strings.TrimSpace(ip))
					if ipClean != "" {
						event := events.NewEvent("cpragency")
						event.EventTypes = eventTemplate.EventTypes
						event.EventDate = eventTemplate.EventDate
						event.URL = eventTemplate.URL
						event.IP = ipClean
						result = append(result, event)
					}
				}
			} else {
				result = append(result, eventTemplate)
			}
		} else {
			// Extract IP from body
			ip := common.FindStringWithoutMarkers(body, "IP", "")
			eventTemplate.IP = common.IsIP(ip)
			if eventTemplate.IP != "" || eventTemplate.URL != "" {
				result = append(result, eventTemplate)
			}
		}
	} else {
		return nil, common.NewNewTypeError(subjectLower)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
