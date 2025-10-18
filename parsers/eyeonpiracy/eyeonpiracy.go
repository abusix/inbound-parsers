// Package eyeonpiracy implements the eyeonpiracy parser
package eyeonpiracy

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the eyeonpiracy parser
type Parser struct{}

// stripHTML removes HTML tags from a string
func stripHTML(s string) string {
	tagRe := regexp.MustCompile(`<[^>]*>`)
	return tagRe.ReplaceAllString(s, "")
}

// removeHTML removes HTML tags with optional replacements
func removeHTML(html string, replaceBR bool, replaceWith string) string {
	if replaceBR {
		html = strings.ReplaceAll(html, "<br>", "\n")
		html = strings.ReplaceAll(html, "<br/>", "\n")
		html = strings.ReplaceAll(html, "<br />", "\n")
	}
	if replaceWith != "" {
		tagRe := regexp.MustCompile(`<[^>]*>`)
		return tagRe.ReplaceAllString(html, replaceWith)
	}
	return stripHTML(html)
}

// getLineAfter returns the first line after a marker
func getLineAfter(text, marker string) string {
	idx := strings.Index(text, marker)
	if idx == -1 {
		return ""
	}
	remaining := text[idx+len(marker):]
	lines := strings.Split(remaining, "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0])
	}
	return ""
}

// trySomeDates attempts to extract date from various locations in the body
func trySomeDates(body string) string {
	dateStr := getLineAfter(body, "Demand for Immediate Take-Down")
	if dateStr != "" {
		return dateStr
	}
	dateStr = common.FindStringWithoutMarkers(body, "Timestamp:", "")
	return dateStr
}

// parseVietnamVersion parses the Vietnam format of eyeonpiracy emails
func parseVietnamVersion(body string, event *events.Event) error {
	url := strings.Trim(common.FindStringWithoutMarkers(body, "URL", ""), " :")
	ip := common.FindStringWithoutMarkers(body, "IP", "")
	date := common.FindStringWithoutMarkers(body, "Timestamp", "")
	work := strings.Trim(common.FindStringWithoutMarkers(body, "Content infringed", ""), " :")
	owner := strings.Trim(common.FindStringWithoutMarkers(body, "Content owner", ""), " *:")

	if url == "" {
		return common.NewParserError("Infringing url not found")
	}
	if ip == "" {
		return common.NewParserError("Infringing ip not found")
	}
	if date == "" {
		return common.NewParserError("Infringing date not found")
	}
	if work == "" {
		return common.NewParserError("Infringing work not found")
	}
	if owner == "" {
		return common.NewParserError("Infringing owner not found")
	}

	event.URL = url
	copyright := events.NewCopyright(work, owner, "")
	event.EventTypes = []events.EventType{copyright}
	event.IP = ip
	event.EventDate = email.ParseDate(date)

	return nil
}

// parseListOfCopyrightedWork parses format with list of URLs and IPs
func parseListOfCopyrightedWork(serializedEmail *email.SerializedEmail, body string) ([]*events.Event, error) {
	var result []*events.Event

	date := common.FindStringWithoutMarkers(body, "Notice Date:", "")
	owner := strings.TrimSuffix(strings.TrimSpace(common.FindStringWithoutMarkers(body, "our client", "")), ".")
	officialURL := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Official URL", ")"))

	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "http") && strings.Contains(line, "(IP :") {
			parts := strings.Split(line, "(IP :")
			if len(parts) != 2 {
				continue
			}
			url := strings.TrimSpace(parts[0])
			ip := strings.TrimSuffix(strings.TrimSpace(parts[1]), ")")

			event := events.NewEvent("eyeonpiracy")
			event.EventDate = email.ParseDate(date)
			event.IP = ip
			event.URL = url
			copyright := events.NewCopyright("", owner, "")
			copyright.OfficialURL = officialURL
			event.EventTypes = []events.EventType{copyright}
			result = append(result, event)
		}
	}

	return result, nil
}

// parseNormalVersion parses the standard eyeonpiracy email format
func parseNormalVersion(serializedEmail *email.SerializedEmail, body, rawBody string, event *events.Event) error {
	copyright := events.NewCopyright("", "", "")

	// Try to extract date from body
	dateStr := trySomeDates(body)
	if dateStr != "" {
		event.EventDate = email.ParseDate(dateStr)
	}
	if event.EventDate == nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	owner := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Copyright owner:", ""))
	work := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Copyrighted work(s):", ""))
	if work == "" {
		work = strings.Trim(common.GetNonEmptyLineAfter(body, "Copyrighted work(s):"), " -*")
	}
	material := strings.TrimSpace(common.GetNonEmptyLineAfter(body, "Copyright infringing material"))

	workLower := strings.ToLower(work)
	materialLower := strings.ToLower(material)

	if workLower == "see below" || strings.Contains(materialLower, "below") || strings.Contains(materialLower, "locations(s)") {
		if !strings.Contains(rawBody, "<h3>") {
			// Parse data part from plain text
			dataSection := common.FindStringWithoutMarkers(body, "E-mail:", "--")
			lines := strings.Split(dataSection, "\n")
			var dataPart []string
			for _, line := range lines[1:] {
				if strings.TrimSpace(line) != "" {
					dataPart = append(dataPart, line)
				}
			}
			if len(dataPart) >= 2 {
				material = dataPart[1]
				work = dataPart[0]
			}
		} else {
			// Parse HTML version
			if workLower == "see below" {
				work = ""
			}

			// Extract section after <h3>
			h3Idx := strings.Index(rawBody, "<h3>")
			if h3Idx != -1 {
				temp := removeHTML(rawBody[h3Idx:], false, "\n")
				temp = strings.TrimSpace(temp)

				var dataPart []string
				for _, line := range strings.Split(temp, "\n") {
					if strings.TrimSpace(line) != "" {
						dataPart = append(dataPart, strings.TrimSpace(line))
					}
				}

				if work == "" && len(dataPart) > 0 {
					work = dataPart[0]
				}

				// Process remaining lines
				dateStr := ""
				for _, value := range dataPart[1:] {
					valueLower := strings.ToLower(value)
					if strings.Contains(valueLower, "official url") {
						parts := strings.SplitN(value, ":", 2)
						if len(parts) == 2 {
							copyright.OfficialURL = strings.TrimSpace(parts[1])
						}
					} else if strings.Contains(valueLower, "source") {
						// data_source would be stored here in Python
						// Not implemented in Go events yet
					} else if strings.Contains(value, "(IP") {
						parts := strings.SplitN(value, ":", 2)
						if len(parts) == 2 {
							event.IP = strings.TrimSpace(parts[1])
						}
					} else if strings.Contains(valueLower, "started at") {
						parts := strings.SplitN(value, "at ", 2)
						if len(parts) == 2 {
							dateStr = strings.TrimSpace(parts[1])
						}
					} else {
						material = strings.TrimSpace(value)
					}
				}

				if dateStr != "" {
					// Format: remove last 4 chars and add :00:00 UTC
					if len(dateStr) > 4 {
						dateStr = dateStr[:len(dateStr)-4] + ":00:00 UTC"
					}
					event.EventDate = email.ParseDate(dateStr)
				}
			}
		}
	} else {
		return common.NewParserError("New type detected, adapt the parser")
	}

	if work == "" || material == "" {
		return common.NewParserError("Some data is missing")
	}

	copyright.CopyrightedWork = work
	copyright.CopyrightOwner = owner
	event.URL = material
	event.EventTypes = []events.EventType{copyright}

	return nil
}

// Parse parses emails from eyeonpiracy@* or @leakid.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	event := events.NewEvent("eyeonpiracy")
	rawBody, err := common.GetBody(serializedEmail, false)
	if err != nil || rawBody == "" {
		return nil, common.NewParserError("email body is empty")
	}

	body := removeHTML(rawBody, true, "")

	// Check for Vietnam version
	bodyTrimmed := strings.TrimSpace(body)
	if strings.HasPrefix(bodyTrimmed, "Notice ID:") &&
		strings.Contains(body, "Identification and localization of the infringing material") {
		if err := parseVietnamVersion(body, event); err != nil {
			return nil, err
		}
		return []*events.Event{event}, nil
	}

	// Check for list of copyrighted work version
	if strings.Contains(strings.ToLower(body), "list of works and infringing url") &&
		strings.Contains(body, "IP :") {
		return parseListOfCopyrightedWork(serializedEmail, body)
	}

	// Parse normal version
	if err := parseNormalVersion(serializedEmail, body, rawBody, event); err != nil {
		return nil, err
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
