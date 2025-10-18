// Package threeantsds implements the 3antsds copyright parser
package threeantsds

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

var (
	officialURLPattern = regexp.MustCompile(`(?i)an authorized example of the content is available at[^h.]*http([^\s]+)`)
	httpOrHTTPS        = regexp.MustCompile(`^(?P<url>https?://\S+)`)
	workURLs           = regexp.MustCompile(`^((?P<name>.+)\s{0,2})?(?P<urls>(https?://\S+\s?)+)`)
)

// Parser implements the threeantsds parser
type Parser struct{}

// Parse parses copyright infringement emails from 3antsds
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, _ := common.GetSubject(serializedEmail, false)

	// Get event date
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)

	// Check if this is a copyright/takedown email
	if strings.Contains(bodyLower, "list of the url's to take down") ||
		strings.Contains(bodyLower, "infringing urls") ||
		strings.Contains(subjectLower, "dmca") {

		// Check for simple copyright format
		if strings.Contains(subjectLower, "urgent") ||
			strings.Contains(subjectLower, "takedown request - copyright infringement - on behalf") {
			return parseSimpleCopyrights(body, eventDate)
		}

		// Parse standard copyright format
		return parseCopyrights(body, eventDate)
	}

	// Handle HTML table format
	originalURL := common.FindStringWithoutMarkers(body, "URL:&nbsp;&nbsp;", " ")
	if originalURL != "" {
		event := events.NewEvent("threeantsds")
		event.EventDate = eventDate
		event.URL = strings.TrimSpace(common.GetNonEmptyLineAfter(body, "URL: "))

		if ip := common.GetNonEmptyLineAfter(body, "IP:"); ip != "" {
			if validIP := common.IsIP(ip); validIP != "" {
				event.IP = validIP
			}
		}

		copyright := &events.Copyright{
			BaseEventType: events.BaseEventType{Name: "copyright", Type: "copyright"},
			OfficialURL:   originalURL,
		}
		event.EventTypes = []events.EventType{copyright}

		return []*events.Event{event}, nil
	}

	// Parse HTML table format
	return parseHTMLTable(body, eventDate)
}

func parseSimpleCopyrights(body string, eventDate *time.Time) ([]*events.Event, error) {
	bodyLower := strings.ToLower(body)

	copyrightedWork := common.FindStringWithoutMarkers(bodyLower, "the live event work", "has been uploaded")
	if copyrightedWork != "" {
		copyrightedWork = strings.TrimSpace(copyrightedWork)
		copyrightedWork = strings.Title(copyrightedWork)
	}

	infringingURL := common.FindStringWithoutMarkers(bodyLower, "infringing urls:", "\n")
	infringingURL = strings.ReplaceAll(infringingURL, "*", "")
	infringingURL = strings.TrimSpace(infringingURL)

	ip := common.FindStringWithoutMarkers(bodyLower, "ip:", "\n")

	event := createEvent(eventDate, infringingURL, copyrightedWork, "", "", ip, "")
	return []*events.Event{event}, nil
}

func parseCopyrights(body string, eventDate *time.Time) ([]*events.Event, error) {
	bodyLower := strings.ToLower(body)

	copyrightedWorkType := common.FindStringWithoutMarkers(bodyLower, "kind of work:", "\n")
	if copyrightedWorkType != "" {
		copyrightedWorkType = strings.Title(strings.TrimSpace(copyrightedWorkType))
		copyrightedWorkType = strings.ReplaceAll(copyrightedWorkType, ".", "")
	}

	ip := common.FindStringWithoutMarkers(bodyLower, "ip:", "\n")
	if ip != "" {
		ip = strings.TrimSpace(ip)
	}

	var eventsList []*events.Event

	if checkDifferentType(body) {
		// Handle multiple works format
		newBody := getImportantBody(body)
		marker1 := "authorized example of the content is available at:"
		marker2 := "allegedly infringing urls:"

		// Split by work markers
		for _, el := range strings.Split(newBody, "\r\n*") {
			for _, work := range strings.Split(el, "\r\nWORK: *") {
				workLower := strings.ToLower(work)
				if strings.Contains(workLower, marker1) && strings.Contains(workLower, marker2) {
					work = rearrangeWork(work, []string{marker1, marker2})
					copyrightedWork := common.GetNonEmptyLineAfter(work, "work:")
					copyrightedWork = strings.ReplaceAll(copyrightedWork, "*", "")
					officialURL := common.GetNonEmptyLineAfter(work, marker1)
					infringingURL := common.GetNonEmptyLineAfter(work, marker2)

					event := createEvent(eventDate, infringingURL, copyrightedWork, officialURL, copyrightedWorkType, ip, "")
					eventsList = append(eventsList, event)
				}
			}
		}
	} else {
		// Single work format
		copyrightedWork := ""
		officialURL := ""

		// Extract official URL
		if match := officialURLPattern.FindStringSubmatch(body); len(match) > 1 {
			officialURL = "http" + match[1]
		}

		newBody := getImportantBody(body)

		var topics [][]string
		if strings.Contains(newBody, "*") {
			parts := strings.Split(newBody, "*")
			var filtered []string
			for _, p := range parts {
				if p != "" {
					filtered = append(filtered, p)
				}
			}
			// Chunk into pairs
			for i := 0; i < len(filtered); i += 2 {
				if i+1 < len(filtered) {
					topics = append(topics, []string{filtered[i], filtered[i+1]})
				} else {
					topics = append(topics, []string{filtered[i]})
				}
			}
		} else {
			topics = [][]string{{"", newBody}}
		}

		for _, topic := range topics {
			publisher := ""
			data := ""
			if len(topic) == 2 {
				publisher = topic[0]
				data = topic[1]
			} else if len(topic) == 1 {
				data = topic[0]
			}

			data = strings.TrimSpace(data)

			// Extract work and URLs
			matches := workURLs.FindAllStringSubmatch(data, -1)
			for _, workAndURLData := range matches {
				if len(workAndURLData) < 4 {
					continue
				}

				work := ""
				if len(workAndURLData) > 2 {
					work = workAndURLData[2]
				}

				urlsData := ""
				if len(workAndURLData) > 3 {
					urlsData = workAndURLData[3]
				}

				var urls []string
				for _, line := range strings.Split(urlsData, "\n") {
					line = strings.TrimSpace(line)
					if line != "" {
						urls = append(urls, line)
					}
				}

				if work != "" {
					workLower := strings.ToLower(work)
					if !strings.Contains(workLower, "www") &&
						!strings.Contains(workLower, "://") &&
						!strings.Contains(workLower, "infringing urls") {
						copyrightedWork = strings.Trim(work, "\n\t,.")
					}
				}

				for _, url := range urls {
					if !strings.Contains(url, "copyrightclaim") {
						event := createEvent(eventDate, url, copyrightedWork, officialURL, copyrightedWorkType, ip, publisher)
						eventsList = append(eventsList, event)
					}
				}
			}
		}
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no copyright events found")
	}

	return eventsList, nil
}

func parseHTMLTable(body string, eventDate *time.Time) ([]*events.Event, error) {
	// Simple HTML table parsing
	// Extract original URL from first table
	originalURL := ""

	// Find table content between <table> tags
	tableStart := strings.Index(body, "<table")
	if tableStart == -1 {
		return nil, common.NewParserError("no HTML table found")
	}

	// Extract text from li elements to get original URL
	if liStart := strings.Index(body[tableStart:], "<li>"); liStart != -1 {
		liEnd := strings.Index(body[tableStart+liStart:], "</li>")
		if liEnd != -1 {
			liText := body[tableStart+liStart : tableStart+liStart+liEnd]
			// Extract last word (URL)
			words := strings.Fields(liText)
			if len(words) > 0 {
				originalURL = words[len(words)-1]
			}
		}
	}

	// Remove HTML tags and extract data
	pure := regexp.MustCompile(`</?[^>]*>`).ReplaceAllString(body, "\n")
	var data []string
	for _, line := range strings.Split(pure, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			data = append(data, trimmed)
		}
	}

	if len(data) < 2 {
		return nil, common.NewParserError("insufficient data in HTML table")
	}

	data = data[2:] // Skip header rows

	var eventsList []*events.Event
	// Each record is 8 fields
	for index := 0; index < len(data)/8; index++ {
		event := events.NewEvent("threeantsds")
		event.EventDate = eventDate
		event.URL = data[index*8+1]

		ipStr := data[index*8+3]
		if validIP := common.IsIP(ipStr); validIP != "" {
			event.IP = validIP
		}

		copyright := &events.Copyright{
			BaseEventType: events.BaseEventType{Name: "copyright", Type: "copyright"},
			OfficialURL:   originalURL,
		}
		event.EventTypes = []events.EventType{copyright}

		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

func createEvent(
	date *time.Time,
	infringingURL string,
	copyrightedWork string,
	officialURL string,
	copyrightedWorkType string,
	ip string,
	owner string,
) *events.Event {
	event := events.NewEvent("threeantsds")

	copyright := &events.Copyright{
		BaseEventType:   events.BaseEventType{Name: "copyright", Type: "copyright"},
		CopyrightedWork: copyrightedWork,
		OfficialURL:     officialURL,
		CopyrightOwner:  owner,
	}
	event.EventTypes = []events.EventType{copyright}

	event.URL = infringingURL
	event.EventDate = date

	if ip != "" {
		if validIP := common.IsIP(ip); validIP != "" {
			event.IP = validIP
		}
	}

	return event
}

func getImportantBody(body string) string {
	markers := []string{"infringing urls:", "kind of work:", "allegedly infringing urls"}
	bodyLower := strings.ToLower(body)
	startIndex := 0

	for _, marker := range markers {
		if index := strings.Index(bodyLower, marker); index > startIndex {
			startIndex = index + len(marker)
		}
	}

	endIndex := len(body)
	endMarkers := []string{
		"according to the protocol copyright act",
		"authorized example of the content is available at",
	}

	for _, marker := range endMarkers {
		if strings.Contains(bodyLower, marker) {
			if idx := strings.Index(bodyLower, marker); idx != -1 {
				endIndex = idx
				break
			}
		}
	}

	lines := strings.Split(body[startIndex:endIndex], "\n")
	if len(lines) > 2 {
		lines = lines[1 : len(lines)-1]
	}

	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func checkDifferentType(body string) bool {
	allWorks := []string{}
	for _, line := range strings.Split(strings.ToLower(body), "\n") {
		if strings.HasPrefix(line, "work:") {
			allWorks = append(allWorks, line)
		}
	}
	return len(allWorks) > 1
}

func rearrangeWork(work string, markers []string) string {
	work = "work:\n\n" + strings.ToLower(work)
	for _, m := range markers {
		work = strings.ReplaceAll(work, m, m+"\n\n")
	}
	return work
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
