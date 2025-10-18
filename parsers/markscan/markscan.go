package markscan

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

var (
	urlPattern   = regexp.MustCompile(`http\S+`)
	htmlTags     = regexp.MustCompile(`<[^>]+>`)
	urlSeqPattern = regexp.MustCompile(`\d\s+http\S+\s+(?P<url>\S+)`)
)

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("email body is empty")
	}

	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	var result []*events.Event

	if strings.Contains(subjectLower, "indian ") && strings.Contains(subjectLower, "copyright") {
		result, err = parseIndianCopyright(serializedEmail, body)
	} else if strings.Contains(subjectLower, "copyright") || strings.Contains(subjectLower, "infringement report") {
		result, err = parseCopyright(serializedEmail, body)
	} else {
		return nil, common.NewNewTypeError(subjectLower)
	}

	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, common.NewParserError("no events created")
	}

	return result, nil
}

func parseCopyright(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	bodyLower := strings.ToLower(body)
	var eventsList []*events.Event
	var urlCandidates []string
	var ip string
	urls := make(map[string]bool)

	// Extract infringing material from <strong> tags
	var infringingMaterial string
	if strings.Contains(body, "<strong>") {
		startIdx := strings.Index(body, "<strong>") + len("<strong>")
		endIdx := strings.Index(body[startIdx:], "</strong>")
		if endIdx != -1 {
			infringingMaterial = strings.Trim(body[startIdx:startIdx+endIdx], " '")
		}
	}

	// Process body line by line
	lines := strings.Split(body, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(lines[i], "<tr>", ""), "<td>", ""))

		// Check for URL section markers
		if regexp.MustCompile(`(?i)Below (is|are|is/are) the (details of the pirated )?URL`).MatchString(line) ||
			strings.Contains(line, "sample of infringement") {
			urlsFound := false
			for j := i + 1; j < len(lines); j++ {
				candidates := strings.Split(
					strings.TrimSpace(
						strings.ReplaceAll(
							strings.ReplaceAll(
								strings.ReplaceAll(
									strings.ReplaceAll(lines[j], "<tr>", ""),
									"</tr>", ""),
								"<td>", ""),
							"</td>", "")),
					"<br>")
				for _, entry := range candidates {
					urlCandidates = append(urlCandidates, strings.TrimSpace(entry))
				}

				lineTrimmed := strings.TrimSpace(lines[j])
				if lineTrimmed == "" && urlsFound {
					break
				} else if lineTrimmed != "" {
					urlsFound = true
				}
			}
		} else if strings.Contains(line, "IP Address") {
			ip = common.ExtractOneIP(line)
			ip = common.IsIP(ip)
		}
	}

	// Extract URLs from candidates
	for _, candidate := range urlCandidates {
		if match := urlPattern.FindString(candidate); match != "" {
			urls[match] = true
		}
	}

	// Fallback 1: Look for "infringing website:"
	if len(urls) == 0 && strings.Contains(bodyLower, "infringing website:") {
		block := common.GetBlockAround(bodyLower, "infringing website:")
		for _, line := range block {
			if strings.HasPrefix(line, "http") {
				urls[line] = true
			}
		}
	}

	// Fallback 2: Look for "your reference:" with HTML
	if len(urls) == 0 && strings.Contains(bodyLower, "your reference:") && strings.Contains(body, "</td></tr>") {
		// Strip HTML tags (BeautifulSoup equivalent)
		soup := htmlTags.ReplaceAllString(body, "")
		potentialURLs := common.GetNonEmptyLineAfter(soup, "your reference:")
		for _, urlPart := range strings.Split(potentialURLs, " ") {
			if strings.HasPrefix(urlPart, "http") {
				urls[urlPart] = true
			}
		}
	}

	// Fallback 3: Look for "your reference:" without HTML restriction
	if len(urls) == 0 && strings.Contains(bodyLower, "your reference:") {
		potentialURLs := common.GetBlockAfterWithStop(bodyLower, "your reference:", "")
		for _, url := range potentialURLs {
			if strings.HasPrefix(url, "http") {
				urls[url] = true
			} else if len(urls) > 0 {
				break
			}
		}
	}

	// Fallback 4: Look for "your reference" with markers
	if len(urls) == 0 && strings.Contains(bodyLower, "your reference") {
		endMarker := "IP Address"
		if strings.Contains(body, "Cloudflare Ticket ID") {
			endMarker = "Cloudflare Ticket ID"
		}
		urlBlock := common.FindStringWithoutMarkers(body, "for your reference", endMarker)
		if urlBlock != "" {
			for _, line := range strings.Split(urlBlock, "\n") {
				if strings.Contains(line, "http") {
					urls[line] = true
				}
			}
		}
	}

	// Fallback 5: Look for "URL:"
	if len(urls) == 0 && strings.Contains(body, "URL:") {
		url := common.FindStringWithoutMarkers(body, "URL:", "")
		if url != "" {
			urls[url] = true
		}
	}

	// Fallback 6: Look for specific table pattern
	if len(urls) == 0 && strings.Contains(body, "S. No. Infringing URLs Infringing Website Official URLs") {
		if match := urlSeqPattern.FindStringSubmatch(body); len(match) > 1 {
			urls[match[len(match)-1]] = true
		}
	}

	// Fallback 7: Use subject as URL
	if len(urls) == 0 {
		subject, err := common.GetSubject(serializedEmail, true)
		if err != nil {
			return nil, err
		}
		urls[subject] = true
		ip = common.FindStringWithoutMarkers(bodyLower, "ip:", "")
	}

	// Get event date
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	// Create events
	for url := range urls {
		event := events.NewEvent("markscan")
		if ip != "" {
			event.IP = ip
		}
		event.URL = url
		event.EventDate = eventDate
		event.EventTypes = []events.EventType{
			events.NewCopyright(infringingMaterial, "", ""),
		}
		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

func parseIndianCopyright(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	var eventsResult []*events.Event
	urls := make(map[string]bool)
	var copyrightedWork string
	var ip string

	// Process body line by line
	lines := strings.Split(body, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(lines[i], "<tr>", ""), "<td>", ""))

		if strings.Contains(line, "website:") {
			startIdx := strings.Index(line, "<br>")
			if startIdx != -1 {
				startIdx += len("<br>")
				endIdx := strings.Index(line[startIdx:], "</B>")
				if endIdx != -1 {
					urlsPart := line[startIdx : startIdx+endIdx]
					for _, url := range strings.Split(urlsPart, "<br>") {
						urls[url] = true
					}
				}
			}
		} else if strings.Contains(line, "in relation to ") {
			startIdx := strings.Index(line, "<B>")
			if startIdx != -1 {
				startIdx += len("<B>")
				endIdx := strings.Index(line[startIdx:], "</B>")
				if endIdx != -1 {
					copyrightedWork = strings.TrimSpace(line[startIdx : startIdx+endIdx])
				}
			}
		}
	}

	// Fallback: look for "url -" pattern
	bodyLower := strings.ToLower(body)
	if len(urls) == 0 && strings.Contains(bodyLower, "url -") {
		cleanBody := strings.ReplaceAll(bodyLower, "*", "")
		urlStr := strings.TrimSpace(common.FindStringWithoutMarkers(cleanBody, "url -", ""))
		if urlStr != "" {
			urls[urlStr] = true
		}
		ip = strings.TrimSpace(common.FindStringWithoutMarkers(cleanBody, "ip address -", ""))
	}

	// Get event date
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	// Create events
	for url := range urls {
		event := events.NewEvent("markscan")
		if ip != "" {
			event.IP = ip
		}
		event.URL = strings.TrimSpace(url)
		event.EventDate = eventDate
		event.EventTypes = []events.EventType{
			events.NewCopyright(copyrightedWork, "", ""),
		}
		eventsResult = append(eventsResult, event)
	}

	return eventsResult, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
