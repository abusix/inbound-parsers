package datapacket

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

		// Special handling for "date" header
		if key == "date" {
			// Parse the date with format: "06 Mar 2023, at 22:12:47 UTC"
			parsedDate := parseForwardedDate(value, []string{"%d %b %Y, at %H:%M:%S utc"})
			if parsedDate != nil {
				headerDict["date"] = []string{parsedDate.Format(time.RFC1123Z)}
			} else {
				// Fallback to original date header
				if origDate, ok := serializedEmail.Headers["date"]; ok && len(origDate) > 0 {
					headerDict["date"] = []string{origDate[0]}
				}
			}
		} else {
			headerDict[key] = []string{value}
		}
	}

	return headerDict
}

// parseForwardedDate parses a date string with the given Python strftime formats
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
		// %d -> 2, %b -> Jan, %Y -> 2006, %H -> 15, %M -> 04, %S -> 05
		goFormat := pyFormat
		goFormat = strings.ReplaceAll(goFormat, "%d", "2")
		goFormat = strings.ReplaceAll(goFormat, "%b", "Jan")
		goFormat = strings.ReplaceAll(goFormat, "%Y", "2006")
		goFormat = strings.ReplaceAll(goFormat, "%H", "15")
		goFormat = strings.ReplaceAll(goFormat, "%M", "04")
		goFormat = strings.ReplaceAll(goFormat, "%S", "05")
		goFormat = strings.ReplaceAll(goFormat, "utc", "UTC")
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

	// e.g: netcraft.from_datapacket.0.eml
	marker := "forwarded message:"

	// Add newline after marker to ensure proper block extraction
	newBody := strings.ToLower(body)
	newBody = strings.ReplaceAll(newBody, marker, marker+"\n")

	// Extract header block after the marker
	headerList := common.GetBlockAfterWithStop(newBody, marker, "")

	if len(headerList) == 0 {
		return nil, fmt.Errorf("no forwarded headers found in email body")
	}

	// The last line of the header block marks where to split the body
	lastHeaderLine := headerList[len(headerList)-1]

	// Split body: everything after the last header line becomes the new body
	// Use the original casing version for the split
	parts := strings.SplitN(body, lastHeaderLine, 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("could not split body at last header line")
	}

	updatedBody := parts[1]

	// Extract new headers from the forwarded message
	newHeaders := getNewHeader(headerList, serializedEmail)

	// Modify the serialized email in place (rewrite pattern)
	serializedEmail.Body = updatedBody
	serializedEmail.Headers = newHeaders

	// Create a simple event - the actual parsing will be done by another parser
	// after this rewrite. This is a pass-through to indicate the email was rewritten.
	event := events.NewEvent("datapacket")
	event.EventTypes = []events.EventType{events.NewUnknown()}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
