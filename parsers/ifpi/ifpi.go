package ifpi

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

// parseOldStyle handles old-style IFPI reports with case numbers
func parseOldStyle(body string, caseNum string, serializedEmail *email.SerializedEmail) []*events.Event {
	var result []*events.Event

	// Extract block after "Represented Companies:"
	blocks := common.GetBlockAfterWithStop(body, "Represented Companies:", "")

	// Parse date from email headers
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	for _, urlPart := range blocks {
		// Parse format: "Artist - Title (http://example.com)"
		if strings.Contains(urlPart, "(http") {
			parts := strings.Split(urlPart, " (http")
			if len(parts) == 2 {
				artistTitle := strings.TrimSpace(parts[0])
				urlStr := "http" + strings.Trim(parts[1], "() ")

				event := events.NewEvent("ifpi")
				event.URL = urlStr
				event.EventDate = eventDate
				event.AddEventDetail(&events.ExternalID{ID: caseNum})
				event.EventTypes = []events.EventType{
					events.NewCopyright(artistTitle, "IFPI Represented Companies", ""),
				}
				result = append(result, event)
			}
		}
	}

	return result
}

// parseNewStyle handles new-style IFPI reports with IP addresses
func parseNewStyle(body string, ip string, serializedEmail *email.SerializedEmail) []*events.Event {
	var result []*events.Event

	// Extract block after "Domain and URLs Host"
	dataPart := common.GetBlockAfterWithStop(body, "Domain and URLs Host", "")

	// Parse date from email headers
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	// Skip first 4 lines (header info)
	if len(dataPart) > 4 {
		dataPart = dataPart[4:]
	}

	// Data comes in groups of 4: title, label, url
	// Pattern: every 4th line is title, then label, then url
	for i := 1; i < len(dataPart); i += 4 {
		if i+2 >= len(dataPart) {
			break
		}

		title := strings.TrimSpace(dataPart[i])
		label := strings.TrimSpace(dataPart[i+1])
		url := strings.TrimSpace(dataPart[i+2])

		if url != "" {
			event := events.NewEvent("ifpi")
			event.URL = url
			event.IP = ip
			event.EventDate = eventDate
			event.EventTypes = []events.EventType{
				events.NewCopyright(title, label, ""),
			}
			result = append(result, event)
		}
	}

	return result
}

// cleanEntry removes HTML tags from table entries
func cleanEntry(entry string) string {
	entry = strings.ReplaceAll(entry, "<td>", "")
	entry = strings.ReplaceAll(entry, "</td>", "")
	return strings.TrimSpace(entry)
}

// parseTable handles HTML table format IFPI reports
func parseTable(table string, caseNumber string, serializedEmail *email.SerializedEmail) []*events.Event {
	var result []*events.Event

	// Parse date from email headers
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	// Split table into rows
	rows := strings.Split(table, "</tr>")

	// Extract entries from each row
	var allEntries [][]string
	for _, row := range rows {
		var entry []string
		for _, line := range strings.Split(row, "\n") {
			if strings.Contains(line, "<td>") {
				entry = append(entry, line)
			}
		}
		if len(entry) > 0 {
			allEntries = append(allEntries, entry)
		}
	}

	// Process each entry
	for _, entry := range allEntries {
		if len(entry) < 2 {
			continue
		}

		copyrightOwner := cleanEntry(entry[0])

		// Concatenate all middle fields as copyrighted work
		var copyrightedWork string
		for i := 1; i < len(entry)-1; i++ {
			copyrightedWork += cleanEntry(entry[i])
		}

		// Last field is the URL
		url := cleanEntry(entry[len(entry)-1])

		if common.IsURL(url) {
			event := events.NewEvent("ifpi")
			event.URL = url
			event.EventDate = eventDate
			event.EventTypes = []events.EventType{
				events.NewCopyright(copyrightedWork, copyrightOwner, ""),
			}
			event.AddEventDetail(&events.ExternalCaseInformation{CaseID: caseNumber})
			result = append(result, event)
		}
	}

	return result
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Extract various markers to determine report type
	ip := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Domain and URLs Host IP Address: ", ""))
	caseNum := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Ref: ", ""))

	// Try old-style format (with case number)
	if caseNum != "" {
		events := parseOldStyle(body, caseNum, serializedEmail)
		if len(events) > 0 {
			return events, nil
		}
	}

	// Try new-style format (with IP address)
	if ip != "" {
		events := parseNewStyle(body, ip, serializedEmail)
		if len(events) > 0 {
			return events, nil
		}
	}

	// Try table format
	if strings.Contains(body, "included in the table below") || strings.Contains(body, "infringing material listed above") {
		tableContent := common.FindString(body, "<table", "</table>")
		if tableContent != "" {
			subject, _ := common.GetSubject(serializedEmail, false)
			caseNumber := common.FindStringWithoutMarkers(subject, "REF: ", ")")

			events := parseTable(tableContent, caseNumber, serializedEmail)
			if len(events) > 0 {
				return events, nil
			}
		}
	}

	return nil, common.NewParserError("could not determine report type")
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
