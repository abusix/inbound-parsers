// Package esp implements the esp parser
package esp

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the esp parser
type Parser struct{}

var ipPortPattern = regexp.MustCompile(`(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]):\d{1,5}`)

// Parse parses emails from esp@* and scc@masergy.com for exploit reports
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	event := events.NewEvent("esp")

	ipMatch := ipPortPattern.FindString(body)
	if ipMatch == "" {
		return nil, common.NewParserError("no IP:port pattern found in body")
	}

	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	event.IP = common.ExtractOneIP(ipMatch)

	parts := strings.Split(ipMatch, ":")
	if len(parts) == 2 {
		if port, err := common.ParsePort(parts[1]); err == nil {
			event.Port = port
		}
	}

	startIndex := strings.Index(body, "Type of Attack/Scan: ")
	if startIndex == -1 {
		return nil, common.NewParserError("attack type not found")
	}
	startIndex += len("Type of Attack/Scan: ")

	endIndex := strings.Index(body[startIndex:], "Hosts:")
	if endIndex == -1 {
		return nil, common.NewParserError("attack type end marker not found")
	}

	attackType := strings.Trim(body[startIndex:startIndex+endIndex], "\n\r. \u00a0")
	if strings.ToLower(attackType) != "generic" {
		return nil, common.NewNewTypeError(attackType)
	}

	event.EventTypes = []events.EventType{events.NewExploit()}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
