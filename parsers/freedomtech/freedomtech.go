// Package freedomtech implements the freedomtech parser
package freedomtech

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the freedomtech parser
type Parser struct{}

var (
	// Pattern 1: [ID]type[IP]
	pattern1 = regexp.MustCompile(`\[(\d*)\](.*)\[(.*)\]`)
	// Pattern 2: IP type Report ID
	pattern2 = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(.*)Report (\d*)`)
)

// Parse parses emails from freedomtech
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	var externalID, ip, typeString string

	// Try pattern 1: [ID]type[IP]
	if matches := pattern1.FindStringSubmatch(subject); len(matches) == 4 {
		externalID = matches[1]
		typeString = matches[2]
		ip = matches[3]
	} else if matches := pattern2.FindStringSubmatch(subject); len(matches) == 4 {
		// Try pattern 2: IP type Report ID
		ip = matches[1]
		typeString = matches[2]
		externalID = matches[3]
	} else {
		return nil, common.NewParserError("regex could not find required data")
	}

	event := events.NewEvent("freedomtech")
	event.IP = ip

	// Get date fallback from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate := email.ParseDate(dateHeaders[0])
		event.EventDate = eventDate
	}

	// Add external ID
	event.AddEventDetail(&events.ExternalID{ID: externalID})

	// Determine event type from type string
	typeString = strings.ToLower(strings.TrimSpace(typeString))

	switch typeString {
	case "copyright":
		event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}
	case "hacking attempt":
		event.EventTypes = []events.EventType{events.NewWebHack()}
	case "port-scan":
		event.EventTypes = []events.EventType{events.NewPortScan()}
	case "login-attack":
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	case "malware":
		event.EventTypes = []events.EventType{events.NewMalware("")}
	default:
		return nil, common.NewNewTypeError(typeString)
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
