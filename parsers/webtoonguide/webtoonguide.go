// Package webtoonguide implements the webtoonguide parser
package webtoonguide

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the webtoonguide parser
type Parser struct{}

// Parse parses emails from copyright@webtoonguide.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Get event date fallback
	dateFallback := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateFallback = dateHeaders[0]
	}

	if strings.Contains(subjectLower, "copyright") {
		return parseCopyright(body, dateFallback)
	}

	return nil, common.NewNewTypeError(subjectLower)
}

func parseCopyright(body, dateFallback string) ([]*events.Event, error) {
	var result []*events.Event

	// Extract reporter information
	reporterName := strings.TrimSpace(common.FindStringWithoutMarkers(body, "My Name:", ""))
	reporterEmail := strings.TrimSpace(common.FindStringWithoutMarkers(body, "My email address:", ""))
	reporterCompanyName := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Company name:", ""))
	reporterStreet := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Address:", ""))
	reporterCity := strings.TrimSpace(common.FindStringWithoutMarkers(body, "City:", ""))
	reporterCountry := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Country:", ""))
	reporterAddress := reporterStreet + ", " + reporterCity + ", " + reporterCountry
	reporterPhone := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Telephone:", ""))

	// Create reporter organisation
	reporter := &events.Organisation{
		Name:         "reporter",
		ContactName:  reporterName,
		ContactEmail: reporterEmail,
		ContactPhone: reporterPhone,
		Organisation: reporterCompanyName,
		Address:      reporterAddress,
	}

	// Extract copyright owner
	copyrightOwner := common.FindStringWithoutMarkers(body, "copyright of our customer \"", "\"")

	// Extract URL block
	urlBlock := common.FindStringWithoutMarkers(body, "Infringing URLs:", "■ Describe the original work:")

	// Process each URL
	lines := strings.Split(urlBlock, "\n")
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "http") {
			event := events.NewEvent("webtoonguide")
			eventDate := email.ParseDate(dateFallback)
			event.EventDate = eventDate

			// Add reporter detail
			event.AddEventDetail(reporter)

			// Set copyright event type
			event.EventTypes = []events.EventType{
				events.NewCopyright("", copyrightOwner, ""),
			}

			// Set URL
			event.URL = trimmedLine

			result = append(result, event)
		}
	}

	if len(result) == 0 {
		return nil, common.NewParserError("no URLs found in copyright report")
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
