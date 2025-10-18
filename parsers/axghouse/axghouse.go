package axghouse

import (
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

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)

	var eventsList []*events.Event

	// Set event date from headers
	eventDate := getEventDate(serializedEmail)

	// Check for table format - "provide access to a copyrighted work (s)"
	if strings.Contains(bodyLower, "provide access to a copyrighted work (s)") {
		// Extract HTML table
		rows := parseHTMLTable(body)

		for _, row := range rows {
			event := events.NewEvent("axghouse")
			event.EventDate = eventDate

			// Extract fields from row
			title := row["Title"]
			url := row["Url"]
			ip := row["IP"]

			event.EventTypes = []events.EventType{
				events.NewCopyright(title, "", ""),
			}
			event.URL = url
			event.IP = ip

			eventsList = append(eventsList, event)
		}
	} else {
		// Text-based copyright format
		var copyrightOwner string
		var authorisedWorks string

		// Extract copyright owner from "on behalf of"
		if owner := common.FindStringWithoutMarkers(bodyLower, "on behalf of", ""); owner != "" {
			// Capitalize first letter (equivalent to Python's .capitalize())
			owner = strings.TrimSpace(owner)
			if len(owner) > 0 {
				copyrightOwner = strings.ToUpper(owner[:1]) + strings.ToLower(owner[1:])
			}
		}

		// Extract authorised works
		authorisedTag := "authorised example(s) of the work:"
		tagUntil := ""
		for _, tag := range []string{"letter of authorization:", "power of attorney:"} {
			if strings.Contains(bodyLower, tag) {
				tagUntil = tag
				break
			}
		}

		// Add newline after the tag for better extraction
		bodyWithNewline := strings.Replace(bodyLower, authorisedTag, authorisedTag+"\n", 1)
		if authorised := common.GetBlockAfterWithStop(bodyWithNewline, authorisedTag, tagUntil); len(authorised) > 0 {
			var works []string
			for _, line := range authorised {
				if strings.Contains(line, "http") {
					works = append(works, line)
				}
			}
			authorisedWorks = strings.Join(works, ", ")
		}

		// Extract URLs
		urlsTag := "located at the following urls:"
		bodyWithNewline = strings.Replace(bodyLower, urlsTag, urlsTag+"\n", 1)
		urls := common.GetBlockAfterWithStop(bodyWithNewline, urlsTag, "")

		if len(urls) > 0 {
			for _, url := range urls {
				event := events.NewEvent("axghouse")
				event.EventDate = eventDate

				if strings.Contains(subjectLower, "copyright") {
					event.EventTypes = []events.EventType{
						events.NewCopyright(authorisedWorks, copyrightOwner, ""),
					}
				} else {
					event.EventTypes = []events.EventType{
						events.NewCopyright("", "", ""),
					}
				}

				event.URL = url
				eventsList = append(eventsList, event)
			}
		}
	}

	// Return at least one event if we didn't extract any
	if len(eventsList) == 0 {
		event := events.NewEvent("axghouse")
		event.EventDate = eventDate
		event.EventTypes = []events.EventType{
			events.NewCopyright("", "", ""),
		}
		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

// parseHTMLTable extracts table data from HTML
// Returns a slice of maps where keys are column headers
func parseHTMLTable(html string) []map[string]string {
	var results []map[string]string

	// Extract table content
	tableRegex := regexp.MustCompile(`(?is)<table[^>]*>(.*?)</table>`)
	tableMatches := tableRegex.FindStringSubmatch(html)
	if len(tableMatches) < 2 {
		return results
	}

	tableContent := tableMatches[1]

	// Extract headers
	var headers []string
	thRegex := regexp.MustCompile(`(?is)<th[^>]*>(.*?)</th>`)
	thMatches := thRegex.FindAllStringSubmatch(tableContent, -1)
	for _, match := range thMatches {
		if len(match) > 1 {
			headerText := stripHTMLTags(match[1])
			headers = append(headers, strings.TrimSpace(headerText))
		}
	}

	// If no headers found, return empty
	if len(headers) == 0 {
		return results
	}

	// Extract rows
	trRegex := regexp.MustCompile(`(?is)<tr[^>]*>(.*?)</tr>`)
	trMatches := trRegex.FindAllStringSubmatch(tableContent, -1)

	// Skip first row if it contains headers
	startIdx := 0
	if len(thMatches) > 0 {
		startIdx = 1
	}

	for i := startIdx; i < len(trMatches); i++ {
		if len(trMatches[i]) < 2 {
			continue
		}

		rowContent := trMatches[i][1]

		// Extract cells
		tdRegex := regexp.MustCompile(`(?is)<td[^>]*>(.*?)</td>`)
		tdMatches := tdRegex.FindAllStringSubmatch(rowContent, -1)

		if len(tdMatches) > 0 {
			row := make(map[string]string)
			for j, tdMatch := range tdMatches {
				if len(tdMatch) > 1 && j < len(headers) {
					cellText := stripHTMLTags(tdMatch[1])
					row[headers[j]] = strings.TrimSpace(cellText)
				}
			}
			if len(row) > 0 {
				results = append(results, row)
			}
		}
	}

	return results
}

// stripHTMLTags removes all HTML tags from a string
func stripHTMLTags(html string) string {
	// Remove HTML tags
	re := regexp.MustCompile(`<[^>]*>`)
	return re.ReplaceAllString(html, "")
}

// getEventDate extracts and parses the event date from email headers
func getEventDate(serializedEmail *email.SerializedEmail) *time.Time {
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		return email.ParseDate(dateHeaders[0])
	}
	return nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
