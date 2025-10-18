// Package eisys implements the eisys parser
package eisys

import (
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the eisys parser
type Parser struct{}

// NewParser creates a new eisys parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from eisys.co.jp for copyright infringement reports
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Get date from email header
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	var results []*events.Event

	// Check if this is a copyright infringement report
	if strings.Contains(subject, "Copyright Infringement on your site") {
		reports := extractReports(body)
		for _, report := range reports {
			events := extractEventsFromReport(report, eventDate)
			results = append(results, events...)
		}
	}

	return results, nil
}

// extractReports splits the body into individual reports
// Each report is separated by "---" and we skip the first 4 lines
func extractReports(body string) [][]string {
	var reports [][]string
	var currentReport []string

	lines := strings.Split(body, "\n")

	for idx, line := range lines {
		// Skip first 4 lines
		if idx < 4 {
			continue
		}

		currentReport = append(currentReport, line)

		// Check if this is the end of a report
		if strings.HasPrefix(line, "---") {
			reports = append(reports, currentReport)
			currentReport = []string{}
		}
	}

	return reports
}

// extractEventsFromReport extracts copyright events from a single report
// Format:
// Identification of Copyrighted Work(N):
// The copyrighted work at issue is the file that appears on:
// http://www.example.com/official-url
//
// Identification of Infringed Material(N):
// The copyrighted work at issue is the file which is located at:
// http://www.infringing-site.com/url1
// http://www.infringing-site.com/url2
// ---
func extractEventsFromReport(reportLines []string, date *time.Time) []*events.Event {
	if len(reportLines) == 0 {
		return nil
	}

	// Remove leading empty line if present
	if len(reportLines) > 0 && reportLines[0] == "" {
		reportLines = reportLines[1:]
	}

	var copyrightedWorkURL string
	inInfringementPart := false
	var results []*events.Event

	for _, line := range reportLines {
		lineLower := strings.ToLower(line)
		lineTrimmed := strings.TrimSpace(line)

		// Look for the copyrighted work URL (before the infringement section)
		// It appears after "Identification of Copyrighted Work" header
		if copyrightedWorkURL == "" &&
			strings.HasPrefix(lineLower, "http") &&
			!inInfringementPart {
			copyrightedWorkURL = lineTrimmed
		}

		// Check if we've reached the infringement section
		if strings.HasPrefix(line, "Identification of Infringed Material") {
			if copyrightedWorkURL != "" {
				inInfringementPart = true
			} else {
				// No copyrighted work URL found, skip this report
				return nil
			}
		}

		// Extract infringing URLs from the infringement section
		if inInfringementPart && strings.HasPrefix(lineLower, "http") {
			event := events.NewEvent("eisys")
			event.EventDate = date
			event.URL = lineTrimmed

			// Create copyright event with the official URL
			copyright := events.NewCopyright("", "", "")
			copyright.OfficialURL = copyrightedWorkURL
			event.EventTypes = []events.EventType{copyright}

			results = append(results, event)
		}
	}

	return results
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
