package attributor

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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		subject = ""
	}

	// Validate subject contains expected keywords
	subjectLower := strings.ToLower(subject)
	if !strings.Contains(subjectLower, "dmca") && !strings.Contains(subjectLower, "copyright infringement complaint") {
		return nil, &common.ParserError{Message: "Subject does not contain DMCA or copyright infringement complaint: " + subject}
	}

	// Parse the body to extract reports grouped by domain
	reports := make(map[string]*reportData)
	bodyLines := strings.Split(body, "\n")

	for i := 0; i < len(bodyLines); i++ {
		line := bodyLines[i]
		if strings.HasPrefix(line, "Rights Holder:") {
			// Extract rights holder
			rightsholder := strings.TrimSpace(strings.TrimPrefix(line, "Rights Holder:"))

			// Look ahead for associated fields
			var original string
			for j := i + 1; j < len(bodyLines); j++ {
				nextLine := bodyLines[j]

				// Stop if we hit another Rights Holder section
				if strings.HasPrefix(nextLine, "Rights Holder:") {
					break
				}

				// Extract original work
				if strings.HasPrefix(nextLine, "Original Work:") {
					original = strings.TrimSpace(strings.TrimPrefix(nextLine, "Original Work:"))
				}

				// Extract infringing URL(s)
				if strings.HasPrefix(nextLine, "Infringing URL:") || strings.HasPrefix(nextLine, "Infringing URL(s):") {
					// Split on first colon and get the URL part
					parts := strings.SplitN(nextLine, ":", 2)
					if len(parts) < 2 {
						continue
					}
					url := strings.TrimSpace(parts[1])

					// Extract domain from URL
					domain := extractDomain(url)
					if domain == "" {
						continue
					}

					// Initialize report data for this domain if needed
					if _, exists := reports[domain]; !exists {
						reports[domain] = &reportData{
							urls:          make(map[string]bool),
							originals:     make(map[string]bool),
							rightsholders: make(map[string]bool),
						}
					}

					// Add data to the report
					reports[domain].urls[url] = true
					if original != "" {
						reports[domain].originals[original] = true
					}
					if rightsholder != "" {
						reports[domain].rightsholders[rightsholder] = true
					}
				}
			}
		}
	}

	// Create events from parsed reports
	var result []*events.Event

	for _, reportInfo := range reports {
		// Join rightsholders and originals
		owners := joinSet(reportInfo.rightsholders, " and/or ")
		original := joinSet(reportInfo.originals, " and/or ")

		// Create an event for each URL
		for url := range reportInfo.urls {
			event := events.NewEvent("attributor")
			event.URL = url

			// Set event date if available
			if serializedEmail.Headers != nil {
				if dates, ok := serializedEmail.Headers["date"]; ok && len(dates) > 0 {
					event.EventDate = email.ParseDate(dates[0])
				}
			}

			// Create copyright event type
			copyrightType := events.NewCopyright(original, owners, "")
			event.EventTypes = []events.EventType{copyrightType}

			result = append(result, event)
		}
	}

	if len(result) == 0 {
		return nil, &common.ParserError{Message: "no event created"}
	}

	return result, nil
}

// reportData holds parsed copyright report information for a domain
type reportData struct {
	urls          map[string]bool
	originals     map[string]bool
	rightsholders map[string]bool
}

// extractDomain extracts the domain from a URL
func extractDomain(url string) string {
	// Remove protocol prefix
	parts := strings.SplitN(url, "://", 2)
	domainPart := url
	if len(parts) == 2 {
		domainPart = parts[1]
	}

	// Extract domain (everything before first /)
	if idx := strings.Index(domainPart, "/"); idx != -1 {
		domainPart = domainPart[:idx]
	}

	return domainPart
}

// joinSet joins map keys with a separator
func joinSet(set map[string]bool, sep string) string {
	var items []string
	for item := range set {
		items = append(items, item)
	}
	return strings.Join(items, sep)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
