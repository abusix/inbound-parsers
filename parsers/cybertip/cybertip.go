package cybertip

import (
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
	// Get body - must be present
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Extract report number from subject
	subject, _ := common.GetSubject(serializedEmail, false)
	reportNumber := common.FindStringWithoutMarkers(subject, "Report #", "]")

	// Check if this is a child pornography report (type detection)
	if !strings.Contains(body, "child pornography") {
		return nil, common.NewParserError("New report format, type not detected.")
	}

	// Collect URLs and metadata
	urls := make(map[string]bool)
	var ipStr string
	var imageHash string

	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract URLs from lines starting with "hxxp"
		if strings.HasPrefix(line, "hxxp") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				cleanedURL := common.CleanURL(parts[0])
				urls[cleanedURL] = true

				// Try to extract IP from this line
				if ip := common.ExtractOneIP(line); ip != "" {
					ipStr = ip
				}
			}
		} else if strings.HasPrefix(line, "Path:") || strings.HasPrefix(line, "Image Path:") {
			// Extract URL after "Path:" or "Image Path:"
			_, url, found := strings.Cut(line, ": ")
			if found {
				cleanedURL := common.CleanURL(url)
				urls[cleanedURL] = true
			}
		} else if strings.Contains(strings.ToLower(line), "referring page:") {
			// Extract redirection URL
			_, url, found := strings.Cut(line, ": ")
			if found {
				cleanedURL := common.CleanURL(url)
				urls[cleanedURL] = true
			}
		} else if strings.Contains(strings.ToLower(line), "ip:") {
			// Save the IP line for later extraction
			ipStr = line
		} else if strings.Contains(strings.ToLower(line), "sha1") {
			// Extract SHA1 hash and format it
			imageHash = strings.ToLower(line)
			imageHash = strings.ReplaceAll(imageHash, ": ", "=")
		}
	}

	// Get event date from email headers
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	// Create one event per URL
	var result []*events.Event
	for url := range urls {
		event := events.NewEvent("cybertip")
		event.EventTypes = []events.EventType{events.NewChildAbuse()}
		event.EventDate = eventDate
		event.URL = url
		event.IP = ipStr

		// Add file hash if present
		if imageHash != "" {
			event.AddEventDetail(&events.File{FileHash: imageHash})
		}

		// Add report number as external ID if present
		if reportNumber != "" {
			event.AddEventDetail(&events.ExternalID{ID: reportNumber})
		}

		result = append(result, event)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
