package domainabusereporting

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// extractURLs extracts URLs from the body
func extractURLs(body string) []string {
	var urls []string
	foundURL := false

	lines := strings.Split(body, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if common.IsURL(trimmed) {
			// URL block found
			foundURL = true

			// Check for URLs in brackets or parentheses
			if match := regexp.MustCompile(`[\[\(]\s*(https?://.*?)\s*[\]\)]`).FindStringSubmatch(trimmed); match != nil {
				urls = append(urls, strings.TrimSpace(match[1]))
			}
			urls = append(urls, trimmed)
		} else if foundURL {
			// URL block finished
			break
		}
	}

	return urls
}

// extractIP extracts the first IP address from the body
func extractIP(body string) string {
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		if ip := common.ExtractOneIP(line); ip != "" {
			return ip
		}
	}
	return ""
}

// extractTrademark extracts trademark information from the body
func extractTrademark(body string) *events.Trademark {
	// Try multiple patterns for trademark owner
	var trademarkOwner string
	patterns := []struct {
		start string
		end   string
	}{
		{"trademark owner - ", ""},
		{"infringing on the ", " trademark"},
		{"represent ", " and"},
		{"representing ", " and"},
		{"representatives of ", " and"},
	}

	for _, pattern := range patterns {
		if result := common.FindStringWithoutMarkers(body, pattern.start, pattern.end); result != "" {
			trademarkOwner = result
			break
		}
	}

	// Extract country
	country := common.FindStringWithoutMarkers(body, "jurisdiction of trademark registration - ", "")

	// Extract registration number
	registrationNumber := common.FindStringWithoutMarkers(body, "registration number - ", "")
	if registrationNumber == "" {
		if match := regexp.MustCompile(`wipo: (\d+)`).FindStringSubmatch(body); match != nil {
			registrationNumber = match[1]
		}
	}

	// Extract official URL
	var officialURL string
	officialURL = common.FindStringWithoutMarkers(body, "main website - ", "")
	if officialURL == "" {
		// Try regex patterns for official URL
		urlPatterns := []*regexp.Regexp{
			regexp.MustCompile(`\(\s*original work: (https?://.*)\s*\)`),
			regexp.MustCompile(`official website[^.]*at the following location:\s*(https?://[^ ]*)\.*`),
		}
		for _, pattern := range urlPatterns {
			if match := pattern.FindStringSubmatch(body); match != nil {
				officialURL = match[1]
				break
			}
		}
	}

	var regNumbers []string
	if registrationNumber != "" {
		regNumbers = []string{registrationNumber}
	}

	trademark := &events.Trademark{
		BaseEventType: events.BaseEventType{
			Name: "trademark",
			Type: "trademark",
		},
		TrademarkOwner:      trademarkOwner,
		Country:             country,
		RegistrationNumbers: regNumbers,
		OfficialURL:         officialURL,
	}

	return trademark
}

// extractPiracy extracts copyright/piracy information from the body
func extractPiracy(body string) *events.Copyright {
	copyrightOwner := common.FindStringWithoutMarkers(body, "represent ", " and")
	return &events.Copyright{
		BaseEventType: events.BaseEventType{
			Name: "copyright",
			Type: "copyright",
		},
		CopyrightOwner: copyrightOwner,
	}
}

// extractPhishing extracts phishing information from the body
func extractPhishing(body string) *events.Phishing {
	officialURL := common.FindStringWithoutMarkers(body, "main website - ", "")
	return &events.Phishing{
		BaseEventType: events.BaseEventType{
			Name: "phishing",
			Type: "phishing",
		},
		OfficialURL: officialURL,
	}
}

// generateEvents creates events from extracted data
func generateEvents(urls []string, ip string, eventDate string, eventType events.EventType) []*events.Event {
	var result []*events.Event

	// Parse event date
	parsedDate := email.ParseDate(eventDate)

	// If no URLs, create a single event with just IP
	if len(urls) == 0 {
		event := events.NewEvent("domainabusereporting")
		event.EventDate = parsedDate
		if ip != "" {
			event.IP = ip
		}
		event.EventTypes = []events.EventType{eventType}
		result = append(result, event)
		return result
	}

	// Create an event for each URL
	for _, url := range urls {
		event := events.NewEvent("domainabusereporting")
		event.EventDate = parsedDate
		if url != "" {
			event.URL = url
		}
		// Only set IP for the first event (matching Python's zip_longest behavior with one IP)
		if len(result) == 0 && ip != "" {
			event.IP = ip
		}

		// Set phishing_target for Phishing events
		if phishing, ok := eventType.(*events.Phishing); ok {
			// Create a copy to avoid modifying the original
			phishingCopy := &events.Phishing{
				BaseEventType:  phishing.BaseEventType,
				OfficialURL:    phishing.OfficialURL,
				PhishingTarget: url,
			}
			event.EventTypes = []events.EventType{phishingCopy}
		} else {
			event.EventTypes = []events.EventType{eventType}
		}

		result = append(result, event)
	}

	return result
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	body = strings.ToLower(body)

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subject = strings.ToLower(subject)

	// Extract URLs and IP
	urls := extractURLs(body)
	ip := extractIP(body)

	// Get event date from headers
	var eventDate string
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = dateHeader[0]
	}

	// Must have at least IP or URL
	if ip == "" && len(urls) == 0 {
		return nil, common.NewParserError("No url or ip found")
	}

	// Determine event type based on subject
	var eventType events.EventType

	if subject == "trademark infringement" || subject == "domain takedown" {
		eventType = extractTrademark(body)
		return generateEvents(urls, ip, eventDate, eventType), nil
	} else if subject == "piracy" {
		eventType = extractPiracy(body)
		return generateEvents(urls, ip, eventDate, eventType), nil
	} else if matched, _ := regexp.MatchString(`^phishing domains?( impersonation)?$`, subject); matched || subject != "" {
		eventType = extractPhishing(body)
		return generateEvents(urls, ip, eventDate, eventType), nil
	}

	return nil, common.NewParserError("Unknown subject type: " + subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
