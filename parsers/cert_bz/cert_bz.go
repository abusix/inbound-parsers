package cert_bz

import (
	"fmt"
	"net"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// NewTypeError represents an error when a new/unknown type is encountered
type NewTypeError struct {
	Subject string
}

func (e *NewTypeError) Error() string {
	return fmt.Sprintf("unknown event type in subject: %s", e.Subject)
}

// Parse parses cert_bz emails
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	var results []*events.Event
	subjectLower := strings.ToLower(subject)

	// Parse the log data after 'throughput' tag
	tag := "throughput"
	bodyLower := strings.ToLower(body)
	bodyProcessed := strings.ReplaceAll(bodyLower, tag, tag+"\n")

	if logLine := common.GetNonEmptyLineAfter(bodyProcessed, tag); logLine != "" {
		// TOTAL_MEGABYTES|DATE_TIME|FLOW_ID|IPV4_SRC_ADDR|IPV4_DST_ADDR|IP_DST_PORT|THROUGHPUT
		fields := strings.Split(logLine, "|")
		if len(fields) > 5 {
			event := events.NewEvent("cert_bz")

			// Determine event type based on subject
			if strings.Contains(subjectLower, "ntp amplification") {
				event.EventTypes = []events.EventType{events.NewCVE("ntp", "", "")}
			} else if strings.Contains(subjectLower, "ddos traffic") {
				event.EventTypes = []events.EventType{events.NewDDoS()}
			} else {
				return nil, &NewTypeError{Subject: subject}
			}

			dateTime := fields[1]
			srcIP := fields[3]
			dstIP := fields[4]
			dstPort := fields[5]

			// Try to set IP
			if ip := net.ParseIP(srcIP); ip != nil {
				event.IP = srcIP
			} else {
				return nil, fmt.Errorf("couldn't get IP from source: %s", srcIP)
			}

			// Try to parse event date
			if parsedDate := email.ParseDate(dateTime); parsedDate != nil {
				event.EventDate = parsedDate
			} else {
				// Fall back to email header date
				if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
					if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
						event.EventDate = parsedDate
					}
				}
			}

			// Add target information
			event.AddEventDetail(&events.Target{
				IP:   dstIP,
				Port: dstPort,
			})

			results = append(results, event)
		}
	}

	// Always try to extract IP from subject and create an event
	// This matches Python behavior which yields event after the throughput block
	event := events.NewEvent("cert_bz")

	// Determine event type based on subject
	if strings.Contains(subjectLower, "ntp amplification") {
		event.EventTypes = []events.EventType{events.NewCVE("ntp", "", "")}
	} else if strings.Contains(subjectLower, "ddos traffic") {
		event.EventTypes = []events.EventType{events.NewDDoS()}
	} else {
		return nil, &NewTypeError{Subject: subject}
	}

	// Try to extract IP from subject
	if ip := extractIPFromString(subject); ip != "" {
		event.IP = ip
	} else {
		return nil, fmt.Errorf("couldn't get IP from subject: %s", subject)
	}

	// Set event date from email header
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	results = append(results, event)
	return results, nil
}

// extractIPFromString extracts an IP address from a string
func extractIPFromString(s string) string {
	// Simple IP extraction - look for patterns like xxx.xxx.xxx.xxx
	// Handle obfuscated IPs like [1[.]2[.]3[.]4]
	cleaned := strings.ReplaceAll(s, "[.]", ".")
	cleaned = strings.ReplaceAll(cleaned, "[", "")
	cleaned = strings.ReplaceAll(cleaned, "]", "")

	// Split by spaces and look for IP-like strings
	words := strings.Fields(cleaned)
	for _, word := range words {
		if ip := net.ParseIP(word); ip != nil {
			return word
		}
	}

	return ""
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
