package hostdime

import (
	"fmt"
	"regexp"
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

// basicEventCopyrightParser implements the Python basic_event_copyright_parser function
// It parses copyright event data from the email body
func basicEventCopyrightParser(event *events.Event, body string) error {
	marker := "Evidentiary Information:"
	index := strings.Index(body, marker)
	if index > -1 {
		body = body[index+len(marker):]
	}

	// Parse key-value pairs using the same regex as Python
	// Pattern: (?P<key>.+?): +(?P<value>.+(?:\r?\n?.*)
	pattern := regexp.MustCompile(`(.+?): +(.+(?:\r?\n?.*)*)`)
	matches := pattern.FindAllStringSubmatch(body, -1)

	stripper := "\r\n\t-#> "
	foundDate := false
	foundIdentifying := false
	seen := make(map[string]bool)
	var eventDate *time.Time
	var fileHash, fileName, fileSize string
	var copyrightedWork, copyrightOwner, protocol string

	for _, match := range matches {
		if len(match) < 3 {
			continue
		}

		key := strings.Trim(strings.ToLower(match[1]), stripper)
		value := strings.Trim(match[2], stripper)

		if value == "" || seen[key] {
			continue
		}
		seen[key] = true

		switch {
		case key == "title" || key == "infringed work" || key == "asset" || key == "work title" || key == "content":
			copyrightedWork = value

		case key == "initial infringement timestamp" || key == "first found (utc)":
			if eventDate != nil {
				event.AddEventDetailSimple("first_seen", eventDate)
			}
			// Parse datetime - simplified version
			parsed, err := parseDateTime(value)
			if err == nil {
				eventDate = &parsed
			}
			foundDate = true

		case key == "recent infringement timestamp" || key == "last seen date" || key == "last found (utc)" ||
			key == "coordinated universal time" || key == "timestamp" || key == "monitored at":
			if eventDate != nil {
				event.AddEventDetailSimple("first_seen", eventDate)
			}
			parsed, err := parseDateTime(value)
			if err == nil {
				eventDate = &parsed
			}
			foundDate = true

		case key == "ip address" || key == "infringer's ip address" || key == "infringers ip address":
			event.IP = value
			foundIdentifying = true

		case key == "port" || key == "infringer's port" || key == "port id":
			if port, err := common.ParsePort(value); err == nil {
				event.Port = port
			}

		case key == "type" || key == "protocol" || key == "infringement source":
			protocol = value
			event.AddEventDetail(&events.Torrent{Protocol: value})

		case key == "torrent hash" || key == "torrent hash value":
			fileHash = value

		case key == "filename" || key == "infringing filename" || key == "computer file name" || key == "file name":
			fileName = value

		case key == "filesize" || key == "infringing filesize" || key == "infringing file size" || key == "file size":
			fileSize = value

		case key == "url if applicable" || key == "url" || key == "infringement":
			event.URL = value
			foundIdentifying = true

		case key == "copyright owner" || key == "copyright holder name":
			copyrightOwner = value

		case key == "united states email":
			event.SenderEmail = value
		}
	}

	event.EventDate = eventDate
	event.AddEventDetail(&events.File{
		FileHash: fileHash,
		FileName: fileName,
		FileSize: fileSize,
	})
	event.EventTypes = []events.EventType{events.NewCopyright(copyrightedWork, copyrightOwner, protocol)}

	if !foundIdentifying {
		return common.NewParserError("no ip found")
	}
	if !foundDate {
		return common.NewParserError("no date found")
	}

	return nil
}

// parseDateTime attempts to parse various datetime formats
func parseDateTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)

	// Common formats to try
	formats := []string{
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"01/02/2006 15:04:05",
		"02-Jan-2006 15:04:05",
		time.RFC1123,
		time.RFC1123Z,
	}

	for _, format := range formats {
		if t, err := time.Parse(format, value); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse datetime: %s", value)
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	event := events.NewEvent("hostdime")

	// Check if this is a copyright event with "Evidentiary Information"
	if strings.Contains(body, "Evidentiary Information") {
		if err := basicEventCopyrightParser(event, body); err != nil {
			return nil, err
		}
	} else {
		// Check if subject contains "ddos"
		subject, err := common.GetSubject(serializedEmail, false)
		if err == nil && strings.Contains(strings.ToLower(subject), "ddos") {
			event.EventTypes = []events.EventType{events.NewDDoS()}
			event.IP = subject

			// Get event date from email headers
			if serializedEmail.Headers != nil {
				if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
					// Parse email date
					parsed, err := parseDateTime(dateHeaders[0])
					if err == nil {
						event.EventDate = &parsed
					}
				}
			}
		} else {
			return nil, common.NewNewTypeError("Terrible copied mails from hostdime")
		}
	}

	// Extract ticket ID if present
	bodyLower := strings.ToLower(body)
	if strings.Contains(bodyLower, "ticket id:") {
		ticketID := common.FindStringWithoutMarkers(bodyLower, "ticket id:", "")
		ticketID = strings.Split(ticketID, "<")[0]
		ticketID = strings.TrimSpace(ticketID)
		if ticketID != "" {
			event.AddEventDetail(&events.ExternalID{ID: ticketID})
		}
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
