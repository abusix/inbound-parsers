package colocationamerica

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

// getNewHeader extracts headers from the forwarded message and constructs a new header map
// This matches the Python _get_new_header() function
func getNewHeader(headerList []string, serializedEmail *email.SerializedEmail) map[string][]string {
	headerDict := make(map[string][]string)

	// Parse header lines into key-value tuples
	for _, line := range headerList {
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.ToLower(parts[0])
		value := parts[1]

		// Special handling for "Sent" header - convert to date
		if key == "sent" {
			// Parse the date with format: "Monday, Month DD, YYYY HH:MM AM/PM"
			parsedDate := parseForwardedDate(value, []string{"Monday, January 2, 2006 3:04 PM"})
			if parsedDate != nil {
				headerDict["date"] = []string{parsedDate.Format(time.RFC1123Z)}
			} else {
				// Fallback to original date header
				if origDate, ok := serializedEmail.Headers["date"]; ok && len(origDate) > 0 {
					headerDict["date"] = []string{origDate[0]}
				}
			}
		}

		headerDict[key] = []string{value}
	}

	return headerDict
}

// parseForwardedDate parses a date string with the given formats
// This matches the Python get_forwarded_date() function
func parseForwardedDate(dateStr string, formats []string) *time.Time {
	dateStr = strings.TrimSpace(dateStr)
	if dateStr == "" {
		return nil
	}

	// Convert Python strftime formats to Go time formats
	goFormats := make([]string, len(formats))
	for i, pyFormat := range formats {
		// Convert Python format to Go format
		// %A -> Monday, %B -> January, %d -> 02, %Y -> 2006, %I -> 3, %M -> 04, %p -> PM
		goFormat := pyFormat
		goFormat = strings.ReplaceAll(goFormat, "%A", "Monday")
		goFormat = strings.ReplaceAll(goFormat, "%B", "January")
		goFormat = strings.ReplaceAll(goFormat, "%d", "2")
		goFormat = strings.ReplaceAll(goFormat, "%Y", "2006")
		goFormat = strings.ReplaceAll(goFormat, "%I", "3")
		goFormat = strings.ReplaceAll(goFormat, "%M", "04")
		goFormat = strings.ReplaceAll(goFormat, "%p", "PM")
		goFormats[i] = goFormat
	}

	// Try each format
	for _, format := range goFormats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return &t
		}
	}

	return nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Extract the block of headers around "From:"
	// Filter out lines containing "Original Message"
	headerBlock := common.GetBlockAround(body, "From:")
	var headerList []string
	for _, line := range headerBlock {
		if !strings.Contains(line, "Original Message") {
			headerList = append(headerList, line)
		}
	}

	if len(headerList) == 0 {
		return nil, fmt.Errorf("no forwarded headers found in email body")
	}

	// The last line of the header block marks where to split the body
	lastHeaderLine := headerList[len(headerList)-1]

	// Split body: everything after the last header line becomes the new body
	parts := strings.SplitN(body, lastHeaderLine, 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("could not split body at last header line")
	}

	newBody := parts[1]

	// Extract new headers from the forwarded message
	newHeaders := getNewHeader(headerList, serializedEmail)

	// Modify the serialized email in place (rewrite pattern)
	serializedEmail.Body = newBody
	serializedEmail.Headers = newHeaders

	// Create a simple event - the actual parsing will be done by another parser
	// after this rewrite. This is a pass-through to indicate the email was rewritten.
	event := events.NewEvent("colocationamerica")
	event.EventTypes = []events.EventType{events.NewSpam()}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
