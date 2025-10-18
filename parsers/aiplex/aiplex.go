package aiplex

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	urlPattern = regexp.MustCompile(`http\S+`)
)

func NewParser() *Parser {
	return &Parser{}
}

// parseCopyrightLegal handles emails from legal@aiplex.com
func parseCopyrightLegal(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get body using helper - try raw text first
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("no email body found")
	}

	body = strings.ReplaceAll(body, "\r", "")

	var date, timeStr, ip string

	// Extract copyright owner
	copyrightOwner := strings.TrimSuffix(common.FindStringWithoutMarkers(body, "works from", ""), ".")

	// Parse lines to extract date, time, and IP
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Date") && date == "" {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				date = strings.TrimSpace(parts[len(parts)-1])
			}
		}
		if strings.HasPrefix(line, "Time") && timeStr == "" {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				timeStr = strings.TrimSpace(parts[len(parts)-1])
				// Extract just the time part before space and replace . with :
				timeParts := strings.Split(timeStr, " ")
				if len(timeParts) > 0 {
					timeStr = strings.ReplaceAll(timeParts[0], ".", ":")
				}
			}
		}
		if strings.HasPrefix(line, "IP") && ip == "" {
			ip = common.ExtractOneIP(line)
		}
	}

	// Parse datetime with timezone +0530
	var parsedDate *time.Time
	if date != "" && timeStr != "" {
		eventDate := date + " " + timeStr + " +0530"
		parsedDate = email.ParseDate(eventDate)
	}

	// Fallback to email header date if parsing failed
	if parsedDate == nil {
		if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
			parsedDate = email.ParseDate(dateHeader[0])
		}
	}

	if parsedDate != nil && ip != "" {
		event := events.NewEvent("aiplex")
		event.IP = ip
		event.EventDate = parsedDate
		event.EventTypes = []events.EventType{events.NewCopyright("", copyrightOwner, "")}
		return []*events.Event{event}, nil
	}

	return nil, common.NewParserError("failed to extract required fields")
}

// parseCopyright handles emails from copyright@aiplex.com and dmca@aiplex.com
func parseCopyright(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, _ := common.GetSubject(serializedEmail, false)

	// Strip HTML and normalize whitespace
	soup := body
	soup = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(soup, " ")
	soup = strings.ToLower(soup)
	soup = strings.ReplaceAll(soup, "\n", " ")
	soup = strings.ReplaceAll(soup, " ", "\n")

	// Extract copyright owner
	var copyrightOwner string
	bodyForOwner := strings.ReplaceAll(body, "strong>", "b>")
	ownerRaw := common.FindStringWithoutMarkers(bodyForOwner, "violation of", "</b>")
	if ownerRaw != "" {
		parts := strings.Split(ownerRaw, "<b>")
		if len(parts) > 1 {
			copyrightOwner = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(parts[1], "")
			copyrightOwner = strings.ReplaceAll(copyrightOwner, "\n", "")
		}
	}

	// Extract copyright work from subject
	var copyrightWork string
	if strings.Contains(subject, "-") {
		copyrightWork = strings.TrimSpace(strings.Split(subject, "-")[0])
	}

	// Clean body for IP extraction
	bodyClean := strings.ReplaceAll(body, " :", ":")

	// Create event template
	eventTemplate := events.NewEvent("aiplex")

	// Get date from headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventTemplate.EventDate = email.ParseDate(dateHeader[0])
	}

	// Extract IP address
	ip := strings.TrimSpace(common.FindStringWithoutMarkers(strings.ToLower(bodyClean), "ip address:", "<"))
	eventTemplate.IP = ip

	// Extract server location and ISP
	serverLocation := strings.TrimSpace(common.FindStringWithoutMarkers(bodyClean, "Server Location:", "<"))
	ispName := strings.TrimSpace(common.FindStringWithoutMarkers(bodyClean, "ISP:", "<"))

	// Extract external ID from subject if present
	if strings.Contains(subject, "RefNo:-") {
		parts := strings.Split(subject, "RefNo:-")
		if len(parts) > 1 {
			eventTemplate.AddEventDetail(&events.ExternalID{ID: parts[1]})
		}
	}

	// Add ISP detail
	if ispName != "" || serverLocation != "" {
		eventTemplate.AddEventDetail(&events.ISP{
			ISPName: ispName,
			Country: serverLocation,
		})
	}

	eventTemplate.EventTypes = []events.EventType{events.NewCopyright(copyrightWork, copyrightOwner, "")}

	// Extract URLs
	urlsTags := []string{
		"url for your reference",
		"following content",
		"following url",
		"reference:",
		"infringing url",
	}

	foundURL := false
	for _, tag := range urlsTags {
		urlLine := common.GetNonEmptyLineAfter(soup, tag)
		if urlLine != "" {
			foundURL = true

			// Check if multiple URLs in one line
			if strings.Count(urlLine, "https") > 1 {
				allURLs := strings.Split(urlLine, "https")
				var results []*events.Event
				for _, urlPart := range allURLs {
					if urlPart != "" {
						eventCopy := *eventTemplate
						eventCopy.URL = "https" + urlPart
						results = append(results, &eventCopy)
					}
				}
				return results, nil
			} else {
				eventTemplate.URL = urlLine
				return []*events.Event{eventTemplate}, nil
			}
		}
	}

	// If no URL found with tags, try regex
	if !foundURL {
		matches := urlPattern.FindAllString(soup, -1)
		if len(matches) > 0 {
			// Split the first match by "http" to get all URLs
			urls := strings.Split(matches[0], "http")
			var results []*events.Event
			for _, urlPart := range urls {
				if urlPart != "" {
					eventCopy := *eventTemplate
					eventCopy.URL = "http" + urlPart
					results = append(results, &eventCopy)
				}
			}
			if len(results) > 0 {
				return results, nil
			}
		}
		return nil, common.NewParserError("no URL found adapt the parser")
	}

	return nil, common.NewParserError("no URL found adapt the parser")
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Determine which parser to use based on From address
	fromAddr := ""
	if from, ok := serializedEmail.Headers["from"]; ok && len(from) > 0 {
		fromAddr = strings.ToLower(from[0])
	}

	if strings.Contains(fromAddr, "copyright@aiplex.com") || strings.Contains(fromAddr, "dmca@aiplex.com") {
		return parseCopyright(serializedEmail)
	} else if strings.Contains(fromAddr, "legal@aiplex.com") {
		return parseCopyrightLegal(serializedEmail)
	}

	return nil, common.NewParserError("unknown sender address: " + fromAddr)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
