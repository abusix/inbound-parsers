package ucr_edu

import (
	"fmt"
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
	subject, _ := common.GetSubject(serializedEmail, false)

	// Extract event date from headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	// Check if this is a firewall misconfiguration notification
	subjectLower := strings.ToLower(subject)
	if !strings.Contains(subjectLower, "firewall misconfiguration notification") {
		return nil, fmt.Errorf("unknown subject type: %s", subject)
	}

	var result []*events.Event

	// Look for hosts.tsv attachment in email parts
	for _, part := range serializedEmail.Parts {
		// Check if this part contains hosts.tsv
		if part.Headers != nil {
			// Check content-disposition or content-type for filename
			disposition, hasDisposition := part.Headers["content-disposition"]
			contentType, hasContentType := part.Headers["content-type"]

			isHostsTsv := false
			if hasDisposition {
				for _, disp := range disposition {
					if strings.Contains(disp, "hosts.tsv") {
						isHostsTsv = true
						break
					}
				}
			}
			if !isHostsTsv && hasContentType {
				for _, ct := range contentType {
					if strings.Contains(ct, "hosts.tsv") {
						isHostsTsv = true
						break
					}
				}
			}

			if isHostsTsv {
				// Extract body content
				var bodyStr string
				switch body := part.Body.(type) {
				case string:
					bodyStr = body
				case []byte:
					bodyStr = string(body)
				default:
					continue
				}

				// Parse each line as an IP address
				lines := strings.Split(bodyStr, "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}

					// Create event for each IP
					event := events.NewEvent("ucr_edu")
					event.EventDate = eventDate
					event.IP = line

					// Set event type to Open with LOW severity
					// In Python: event_types = Open(severity='LOW')
					// The Open type doesn't have a severity field in Go, but we can use the service field
					openEvent := events.NewOpen("")
					event.EventTypes = []events.EventType{openEvent}

					result = append(result, event)
				}
			}
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no hosts.tsv attachment found in email")
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
