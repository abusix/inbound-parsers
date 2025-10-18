package antipiracyprotection

import (
	"strings"

	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
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
	bodyLower := strings.ToLower(body)

	// Get date from headers
	var dateFallback string
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		dateFallback = dateHeader[0]
	}

	// Create event template
	eventTemplate := events.NewEvent("antipiracyprotection")
	eventTemplate.EventDate = email.ParseDate(dateFallback)

	var copyrightedWork string
	var infringingStart, infringingStop string

	// Check if this is a Disney report
	if strings.Contains(bodyLower, "disney") {
		copyrightedWork = common.GetBlockAfterWithStop(bodyLower, "copyrighted work(s) infringed upon:", "")[0]
		copyrightedWork = strings.TrimSpace(copyrightedWork)

		eventTemplate.EventTypes = []events.EventType{
			events.NewCopyright(copyrightedWork, "Disney Enterprises, Inc.", ""),
		}

		if strings.Contains(bodyLower, "location of infringing material") {
			infringingStart = "location of infringing material:"
			infringingStop = "important notes for infringing material:"
		} else {
			infringingStart = "representative sample of infringement by website"
			infringingStop = "the works that website is providing"
		}
	} else {
		return nil, common.NewParserError("unknown email type - not disney")
	}

	// Extract IP address
	ipLine := common.FindStringWithoutMarkers(bodyLower, "ip address", "")
	ip := common.ExtractOneIP(ipLine)

	// Extract location info block
	locationInfo := common.FindStringWithoutMarkers(bodyLower, infringingStart, infringingStop)

	var results []*events.Event
	lines := strings.Split(locationInfo, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check if line contains the stop marker
		if strings.Contains(line, infringingStop) {
			break
		}

		// Check if line is a URL
		if common.IsURL(line) {
			// Create a copy of the event template
			eventCopy := *eventTemplate
			// Copy the event types slice
			eventCopy.EventTypes = make([]events.EventType, len(eventTemplate.EventTypes))
			copy(eventCopy.EventTypes, eventTemplate.EventTypes)

			eventCopy.URL = line
			eventCopy.IP = ip
			results = append(results, &eventCopy)
		}
	}

	if len(results) == 0 {
		return nil, common.NewParserError("no URLs found")
	}

	return results, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
