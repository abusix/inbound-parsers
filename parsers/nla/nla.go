package nla

import (
	"fmt"
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

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)

	if strings.Contains(subjectLower, "copyright") {
		return parsePhishing(body, serializedEmail)
	}

	return nil, fmt.Errorf("unknown subject type: %s", subjectLower)
}

func parsePhishing(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	bodyLower := strings.ToLower(body)

	infgMatTag := ""
	orgMatTag := ""

	// Find infringing material tag
	infgTags := []string{
		"infringing copies of the material:",
		"copy url",
		"infringing domain:",
		"pages and pages:",
	}
	for _, tag := range infgTags {
		if strings.Contains(bodyLower, tag) {
			infgMatTag = tag
			break
		}
	}

	// Find original material tag
	orgTags := []string{
		"original article:",
		"original articles:",
		"original articles/website.",
		"original domain:",
		"Original article:",
	}
	for _, tag := range orgTags {
		if strings.Contains(bodyLower, tag) {
			orgMatTag = tag
			break
		}
	}

	owner := common.FindStringWithoutMarkers(body, "the authorisation of ", "")

	// Get event date from headers
	var eventDate *time.Time
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Handle case where neither tag was found
	if infgMatTag == "" && orgMatTag == "" {
		url := common.FindStringWithoutMarkers(bodyLower, "this entire webpage. ", " ")

		event := events.NewEvent("nla")
		event.URL = url
		event.EventDate = eventDate
		event.EventTypes = []events.EventType{
			&events.Copyright{
				BaseEventType: events.BaseEventType{
					Name: "copyright",
					Type: "copyright",
				},
				CopyrightedWork: url,
				CopyrightOwner:  owner,
			},
		}

		return []*events.Event{event}, nil
	}

	// Extract original material block
	orgMaterialText := bodyLower
	if orgMatTag != "" {
		orgMaterialText = strings.Replace(bodyLower, orgMatTag, orgMatTag+"\n\n", 1)
	}
	orgMaterialBlock := common.GetBlockAfterWithStop(orgMaterialText, orgMatTag, "")
	orgLines := orgMaterialBlock

	// Extract infringing material block
	infgMaterialText := bodyLower
	if infgMatTag != "" {
		infgMaterialText = strings.Replace(bodyLower, infgMatTag, infgMatTag+"\n\n", 1)
	}
	infgMaterialBlock := common.GetBlockAfterWithStop(infgMaterialText, infgMatTag, "")
	infgLines := infgMaterialBlock

	// Trim infg_lines if org_mat_tag appears in them
	if orgMatTag != "" {
		for idx, line := range infgLines {
			if strings.Contains(line, orgMatTag) {
				infgLines = infgLines[:idx]
				break
			}
		}
	}

	// Create events from matching lines
	var eventList []*events.Event
	urlRegex := regexp.MustCompile(`(?i)(http[^>]*)`)

	for idx, line := range infgLines {
		if !strings.HasPrefix(line, "original") {
			if matches := urlRegex.FindStringSubmatch(line); matches != nil && len(matches) > 1 {
				urlMatch := matches[1]

				// Get corresponding original material
				orgMaterial := ""
				if idx < len(orgLines) {
					orgMaterial = orgLines[idx]
				}

				event := events.NewEvent("nla")
				event.URL = urlMatch
				event.EventDate = eventDate
				event.EventTypes = []events.EventType{
					&events.Copyright{
						BaseEventType: events.BaseEventType{
							Name: "copyright",
							Type: "copyright",
						},
						CopyrightedWork: urlMatch,
						CopyrightOwner:  owner,
						OfficialURL:     orgMaterial,
					},
				}

				eventList = append(eventList, event)
			}
		}
	}

	return eventList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
