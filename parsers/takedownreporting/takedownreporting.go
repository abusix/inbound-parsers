package takedownreporting

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	ipPattern  = regexp.MustCompile(`(?i)(IP address(:|-))[^.0-9]*(\[?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\]?)`)
	urlPattern = regexp.MustCompile(`(?i)(URL:)?\s*(https?://.*)\s*`)
)

func NewParser() *Parser {
	return &Parser{}
}

func parseTrademark(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body = strings.ReplaceAll(body, "and they", "they")

	var owner, registrationNumber string
	event := events.NewEvent("takedownreporting")

	// Extract IP from pattern
	if match := ipPattern.FindStringSubmatch(body); match != nil && len(match) > 3 {
		event.IP = strings.TrimSpace(match[3])
	}

	// Extract URL from lines
	for _, line := range strings.Split(body, "\n") {
		if match := urlPattern.FindStringSubmatch(line); match != nil && len(match) > 2 {
			event.URL = strings.TrimSpace(match[2])
			break
		}
	}

	// If no IP or URL found, extract from various patterns
	if event.IP == "" && event.URL == "" {
		var infringement string

		// Try various patterns to find owner and infringement
		if regex := regexp.MustCompile(`domain "(.*)".*using the (.*) trademark`); regex.MatchString(body) {
			matches := regex.FindStringSubmatch(body)
			if len(matches) > 2 {
				owner = strings.Split(matches[2], "brand")[0]
				owner = strings.TrimSpace(owner)
				infringement = matches[1]
			}
		} else if regex := regexp.MustCompile(`(We represent|representatives of|representative of|representing|agent of|agent represent|represent the)(.*)(they|\. They)`); regex.MatchString(body) {
			matches := regex.FindStringSubmatch(body)
			if len(matches) > 2 {
				owner = strings.Trim(matches[2], ", ")
				infringement = common.GetNonEmptyLineAfter(body, matches[1])
			}
		} else if regex := regexp.MustCompile(`name and logo of(.*)in its`); regex.MatchString(body) {
			matches := regex.FindStringSubmatch(body)
			if len(matches) > 1 {
				owner = strings.Trim(matches[1], ", ")
				infringement = common.GetNonEmptyLineAfter(body, "name and logo of")
			}
		} else if regex := regexp.MustCompile(`report this domain(.*)(which|that)`); regex.MatchString(body) {
			matches := regex.FindStringSubmatch(body)
			if len(matches) > 1 {
				infringement = strings.Trim(matches[1], ",\" ")
			}
		} else if strings.Contains(strings.ToLower(body), "below-mentioned name") {
			infringement = common.GetNonEmptyLineAfter(body, "below-mentioned name")
		} else if regex := regexp.MustCompile(`representing(.*)(, and)`); regex.MatchString(body) {
			matches := regex.FindStringSubmatch(body)
			if len(matches) > 1 {
				owner = strings.Trim(matches[1], ", ")
				infringement = common.GetNonEmptyLineAfter(body, matches[1])
			}
		} else if regex := regexp.MustCompile(`(.*) is the exclusive owner`); regex.MatchString(body) {
			matches := regex.FindStringSubmatch(body)
			if len(matches) > 1 {
				owner = matches[1]
				infringement = common.GetNonEmptyLineAfter(strings.ToLower(body), "url(s):")
			}
		} else if strings.Contains(body, "Trademark Owner - ") && strings.Contains(strings.ToLower(body), "following location") {
			infringement = common.GetNonEmptyLineAfter(strings.ToLower(body), "following location")
		} else {
			return nil, common.NewParserError("owner/infringement info could not be found")
		}

		// Check if infringement is IP or URL
		if common.IsIP(infringement) != "" {
			event.IP = infringement
		} else {
			event.URL = infringement
		}
	}

	// Extract owner if not found yet
	if owner == "" {
		if regex := regexp.MustCompile(`(?i)(Trademark Owner\s*-?)(.*)`); regex.MatchString(body) {
			matches := regex.FindStringSubmatch(body)
			if len(matches) > 2 {
				owner = strings.TrimSpace(matches[2])
			}
		}
	}

	// Extract registration number
	if regex := regexp.MustCompile(`(?i)(Registration number\s*-?)\s*([0-9]+)`); regex.MatchString(body) {
		matches := regex.FindStringSubmatch(body)
		if len(matches) > 2 {
			registrationNumber = strings.TrimSpace(matches[2])
		}
	}

	// Extract country
	country := strings.Trim(common.FindStringWithoutMarkers(strings.ToLower(body), "trademark registration", ""), " -")

	// Extract official URL
	officialURL := ""
	for _, el := range []string{"main website", "official website:"} {
		if found := strings.Trim(common.FindStringWithoutMarkers(strings.ToLower(body), el, ""), " -"); found != "" {
			officialURL = found
			break
		}
	}

	// Create trademark event type
	var trademark *events.Trademark
	if registrationNumber != "" {
		trademark = &events.Trademark{
			BaseEventType: events.BaseEventType{
				Name: "trademark",
				Type: "trademark",
			},
			TrademarkOwner:      owner,
			OfficialURL:         officialURL,
			RegistrationNumbers: []string{registrationNumber},
			Country:             country,
		}
	} else {
		trademark = &events.Trademark{
			BaseEventType: events.BaseEventType{
				Name: "trademark",
				Type: "trademark",
			},
			TrademarkOwner: owner,
			OfficialURL:    officialURL,
			Country:        country,
		}
	}

	event.EventTypes = []events.EventType{trademark}

	// Set event date from email headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		event.EventDate = email.ParseDate(dateHeader[0])
	}

	return []*events.Event{event}, nil
}

func parsePhishing(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	url := common.FindStringWithoutMarkers(strings.ToLower(body), "the following url: ", " ")
	if url == "" {
		if urlCandidate := common.FindStringWithoutMarkers(strings.ToLower(body), "domain name: ", ""); urlCandidate != "" {
			url = urlCandidate
		} else {
			// Try to find URL with regex
			for _, line := range strings.Split(body, "\n") {
				if match := urlPattern.FindStringSubmatch(line); match != nil && len(match) > 2 {
					url = strings.TrimSpace(match[2])
					break
				}
			}
			if url == "" {
				url = common.GetNonEmptyLineAfter(strings.ToLower(body), "this email server")
			}
		}
	}

	// Add http prefix if not present
	if !strings.Contains(url, "http") && !strings.Contains(url, "hxxp") {
		url = "http://" + url
	}
	url = strings.ReplaceAll(url, ".com.com", ".com")

	// Extract IP
	ip := common.FindStringWithoutMarkers(strings.ToLower(body), "which resolves to the", "ip address")
	if ip == "" {
		if match := ipPattern.FindStringSubmatch(body); match != nil && len(match) > 3 {
			ip = strings.TrimSpace(match[3])
		}
	}

	// Create event if we have IP or URL
	if ip != "" || url != "" {
		event := events.NewEvent("takedownreporting")

		// Set event date from email headers
		if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
			event.EventDate = email.ParseDate(dateHeader[0])
		}

		event.IP = ip
		event.URL = url

		// Create phishing event type
		phishing := &events.Phishing{
			BaseEventType: events.BaseEventType{
				Name: "phishing",
				Type: "phishing",
			},
		}

		event.EventTypes = []events.EventType{phishing}

		return []*events.Event{event}, nil
	}

	return nil, common.NewParserError("no IP or URL found in phishing report")
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)

	// Check if it's a phishing report
	if strings.Contains(bodyLower, "phishing") || strings.Contains(subjectLower, "phishing") {
		return parsePhishing(body, serializedEmail)
	}

	// Check if it's a trademark report
	if strings.Contains(bodyLower, "trademark") || strings.Contains(bodyLower, "we are the authorized representative") {
		return parseTrademark(body, serializedEmail)
	}

	return nil, common.NewParserError("owner/infringement info could not be found")
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
