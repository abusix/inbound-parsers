package streamenforcement

import (
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
	var result []*events.Event

	// Get body (throws error if missing)
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	bodyLower := strings.ToLower(body)

	// Create event template
	eventTemplate := events.NewEvent("streamenforcement")

	// Get event date from headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventTemplate.EventDate = email.ParseDate(dateHeader[0])
	}

	var copyrightedWork, copyrightOwner, officialURL string
	var locationStart, locationStop string

	// Determine which copyright holder and extract relevant fields
	if strings.Contains(bodyLower, "abs-cbn") {
		copyrightedWork = strings.TrimSpace(common.FindStringWithoutMarkers(
			bodyLower, "description of the copyrighted work: ", "url",
		))
		copyrightOwner = "ABS-CBN"
		locationStart = "url:"
		locationStop = "my contact information"
	} else if strings.Contains(bodyLower, "disney enterprises") {
		copyrightedWork = strings.TrimSpace(common.GetNonEmptyLineAfter(
			bodyLower, "copyrighted work(s) infringed upon",
		))
		copyrightOwner = "Disney Enterprises, Inc."
		locationStart = "location of infringing material:"
		locationStop = "important notes"
	} else if strings.Contains(bodyLower, "the copyright work(s) of ufc") ||
		strings.Contains(getSubjectLower(serializedEmail), "infringement for ufc") {
		copyrightedWork = strings.TrimSpace(common.FindStringWithoutMarkers(
			bodyLower, "description of the copyrighted work: ", "url",
		))
		officialURL = strings.TrimSpace(common.FindStringWithoutMarkers(
			bodyLower, "the original copyrighted work can be found here:", "my contact information",
		))
		copyrightOwner = "UFC"
		locationStart = "url:"
		locationStop = "an authorized example"
	} else if strings.Contains(bodyLower, "showtime networks inc.") {
		copyrightedWork = strings.TrimSpace(common.FindStringWithoutMarkers(
			bodyLower, "exclusive copyright rights to the", "broadcast on the showtime network",
		))
		copyrightOwner = "Showtime Networks Inc."
		locationStart = "we are notifying you of copyright infringement of the claimant's" +
			"rights at the following location(s): "
		locationStop = "the claimant demands"
	} else {
		// Unknown type - return error
		identifier := ""
		if serializedEmail.Headers != nil {
			if msgID, ok := serializedEmail.Headers["message-id"]; ok && len(msgID) > 0 {
				identifier = msgID[0]
			}
		}
		return nil, common.NewParserError("unknown streamenforcement type: " + identifier)
	}

	// Set copyright event type
	copyright := events.NewCopyright(copyrightedWork, copyrightOwner, "")
	if officialURL != "" {
		copyright.OfficialURL = officialURL
	}
	eventTemplate.EventTypes = []events.EventType{copyright}

	// Find the start line and extract URLs
	startLine := strings.TrimSpace(common.GetNonEmptyLineAfter(bodyLower, locationStart))
	lines := strings.Split(bodyLower, "\n")

	// Trim all lines
	var trimmedLines []string
	for _, line := range lines {
		trimmedLines = append(trimmedLines, strings.TrimSpace(line))
	}

	// Find the index of the start line
	startIndex := -1
	for i, line := range trimmedLines {
		if line == startLine {
			startIndex = i
			break
		}
	}

	// Extract URLs from lines starting at startIndex
	if startIndex != -1 {
		for i := startIndex; i < len(trimmedLines); i++ {
			line := trimmedLines[i]

			// Check if line starts with http
			if strings.HasPrefix(line, "http") {
				// Create a copy of the event template for this URL
				event := *eventTemplate
				event.URL = line
				result = append(result, &event)
			}

			// Stop if we hit the location_stop marker
			if strings.Contains(line, locationStop) {
				break
			}
		}
	}

	return result, nil
}

// getSubjectLower is a helper to safely get the subject in lowercase
func getSubjectLower(serializedEmail *email.SerializedEmail) string {
	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return ""
	}
	return strings.ToLower(subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
