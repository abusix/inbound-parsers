package chaturbate

import (
	"regexp"
	"strconv"
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
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Check for DMCA in subject
	if !strings.Contains(strings.ToLower(subject), "dmca") {
		return nil, common.NewNewTypeError(subject)
	}

	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	body = strings.ToLower(body)

	// Get date
	eventDate := getDate(body, serializedEmail)

	// Extract copyright owner
	copyrightOwner := ""
	ownerPattern := regexp.MustCompile(`owned (?:by )?([^,]*?)(?:,? a user on our|\.)`)
	if matches := ownerPattern.FindStringSubmatch(body); matches != nil {
		copyrightOwner = strings.Trim(matches[1], "*,")
	}

	// Extract official URL
	officialURL := ""
	officialURLPattern := regexp.MustCompile(`captured without authorization from (.*)\.?`)
	if matches := officialURLPattern.FindStringSubmatch(body); matches != nil {
		urlMatch := strings.TrimSpace(matches[1])
		urlMatch = regexp.MustCompile(`\s+`).ReplaceAllString(urlMatch, "")
		urlMatch = strings.ReplaceAll(urlMatch, "**", "")
		officialURL = strings.Trim(urlMatch, ".")
	}

	// Extract external ID
	var externalID *events.ExternalID
	externalIDPattern := regexp.MustCompile(`\[chaturbate\] (\d+)`)
	if matches := externalIDPattern.FindStringSubmatch(strings.ToLower(subject)); matches != nil {
		externalID = &events.ExternalID{ID: matches[1]}
	}

	// Get reporter information
	reporter := getReporter(body)

	// Get URLs
	urls, err := getURLs(body)
	if err != nil {
		return nil, err
	}

	// Create events for each URL
	var result []*events.Event
	for _, url := range urls {
		event := events.NewEvent("chaturbate")
		event.URL = url
		event.EventDate = eventDate

		// Create copyright event type
		copyright := &events.Copyright{
			BaseEventType: events.BaseEventType{
				Name: "copyright",
				Type: "copyright",
			},
			CopyrightOwner: copyrightOwner,
			OfficialURL:    officialURL,
		}
		event.EventTypes = []events.EventType{copyright}

		if externalID != nil {
			event.AddEventDetail(externalID)
		}
		if reporter != nil {
			event.AddEventDetail(reporter)
		}

		result = append(result, event)
	}

	return result, nil
}

func getDate(body string, serializedEmail *email.SerializedEmail) *time.Time {
	dateStr := common.FindStringWithoutMarkers(body, "support, ", "")
	if dateStr == "" {
		// Fall back to email date header
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			return email.ParseDate(dateHeaders[0])
		}
		return nil
	}

	// Clean up date string
	dateStr = strings.ReplaceAll(dateStr, ",", "")
	dateStr = strings.Title(dateStr)

	// Add :00 before timezone abbreviation
	dateStr = regexp.MustCompile(` ([a-zA-Z]{3})$`).ReplaceAllString(dateStr, ":00 $1")

	// Split into parts
	parts := regexp.MustCompile(`[ :]`).Split(dateStr, -1)
	if len(parts) < 7 {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			return email.ParseDate(dateHeaders[0])
		}
		return nil
	}

	// Ensure hour has leading zero
	hour := parts[3]
	hourInt, _ := strconv.Atoi(hour)
	if hourInt < 10 && len(hour) == 1 {
		parts[3] = "0" + hour
	}

	// Reconstruct date string
	finalDateStr := strings.Join(parts[:3], " ") + " " + strings.Join(parts[3:6], ":") + " " + parts[6]

	// Try to parse with common formats
	formats := []string{
		"Jan 2 2006 15:04:05 MST",
		"January 2 2006 15:04:05 MST",
		"Jan 02 2006 15:04:05 MST",
		"January 02 2006 15:04:05 MST",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, finalDateStr); err == nil {
			return &t
		}
	}

	// Fall back to email date header
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		return email.ParseDate(dateHeaders[0])
	}
	return nil
}

func getReporter(body string) *events.Organisation {
	// Get reporter block
	reporterBlock := common.GetContinuousLinesUntilEmptyLine(body, "to the complaining party")

	// Filter out empty lines
	var filtered []string
	for _, line := range reporterBlock {
		if strings.TrimSpace(line) != "" {
			filtered = append(filtered, line)
		}
	}
	reporterBlock = filtered

	if len(reporterBlock) == 1 {
		reporterBlock = common.GetBlockAfterWithStop(body, "to the complaining party", "i, ")
	}

	if len(reporterBlock) == 0 {
		// Try alternative wording
		reporterBlock = common.GetBlockAfterWithStop(body, "with the complaining party", "i, ")

		// Remove leading URLs
		for len(reporterBlock) > 0 && common.IsURL(reporterBlock[0]) {
			reporterBlock = reporterBlock[1:]
		}
	}

	if len(reporterBlock) < 6 {
		return nil
	}

	reporterName := strings.Trim(reporterBlock[0], "*,")
	reporterCompany := reporterBlock[1]
	reporterAddress := strings.Join(reporterBlock[2:4], ", ")
	reporterEmail := reporterBlock[5]

	if !strings.Contains(reporterEmail, "email:") {
		return nil
	}

	reporterEmail = regexp.MustCompile(`email:\s+`).ReplaceAllString(reporterEmail, "")
	reporterEmail = strings.Trim(reporterEmail, "*,")

	return &events.Organisation{
		Name:         "reporter",
		ContactName:  reporterName,
		Organisation: reporterCompany,
		Address:      reporterAddress,
		ContactEmail: reporterEmail,
	}
}

func getURLs(body string) ([]string, error) {
	var urls []string

	// Try different extraction methods
	if strings.Contains(body, "see urls below") {
		urlStr := common.GetNonEmptyLineAfter(body, "urls:")
		if urlStr != "" {
			urls = append(urls, urlStr)
		}
	} else {
		// Extract from block
		block := common.FindStringWithoutMarkers(body, "infringing the copyrighted work:", "information sufficient to permit contact")
		if block != "" {
			for _, line := range strings.Split(block, "\n") {
				if common.IsURL(line) {
					urls = append(urls, line)
				}
			}
		}
	}

	if len(urls) == 0 {
		block := common.FindStringWithoutMarkers(body, "reported urls:", "dear")
		if block != "" {
			for _, line := range strings.Split(block, "\n") {
				if common.IsURL(line) {
					urls = append(urls, line)
				}
			}
		}
	}

	if len(urls) == 0 {
		block := common.FindStringWithoutMarkers(body, "reported urls:", "thank")
		if block != "" {
			for _, line := range strings.Split(block, "\n") {
				if common.IsURL(line) {
					urls = append(urls, line)
				}
			}
		}
	}

	if len(urls) == 0 {
		block := common.FindStringWithoutMarkers(body, "consent to its use as such.", "thank")
		if block != "" {
			for _, line := range strings.Split(block, "\n") {
				if common.IsURL(line) {
					urls = append(urls, line)
				}
			}
		}
	}

	if len(urls) == 0 {
		lines := common.GetContinuousLinesUntilEmptyLine(body, "with the complaining party")
		for _, line := range lines {
			if common.IsURL(line) {
				urls = append(urls, line)
			}
		}
	}

	if len(urls) == 0 {
		return nil, &common.ParserError{Message: "urls not found"}
	}

	// Clean URLs
	var cleanedURLs []string
	for _, url := range urls {
		cleanedURLs = append(cleanedURLs, strings.Trim(url, "*,"))
	}

	return cleanedURLs, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
