package telenor

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the Telenor parser for compromised account reports from nextmail@telenor.net
type Parser struct{}

var dateFinder = regexp.MustCompile(`(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2})`)

// NewParser creates a new Telenor parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from nextmail@telenor.net
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Normalize line endings
	body = strings.ReplaceAll(body, "\r\n", "\n")

	// Extract user/password (account name)
	userPassword := common.FindStringWithoutMarkers(body, `user/passwd: "`, `"`)
	if userPassword == "" {
		// Try to find it in the subject
		subject, _ := common.GetSubject(serializedEmail, false)
		if subject != "" {
			userPassword = common.FindStringWithoutMarkers(subject, `user: "`, `"`)
		}
	}

	if userPassword == "" {
		return nil, common.NewParserError("could not find user name, which makes resolving impossible")
	}

	// Extract sections from the email body
	lookupLines := common.GetContinuousLinesUntilEmptyLine(body, "Geo-IP lookup:")
	summaryLines := common.GetContinuousLinesUntilEmptyLine(body, "Summary:")

	// Get lookup data without the first line (header)
	lookup := getDataWithoutFirst(lookupLines)

	// Get summary data without the first line (header)
	summary := getDataWithoutFirst(summaryLines)

	// Extract log lines between markers
	logglinjer := common.FindStringWithoutMarkers(body, "Logglinjer:", strings.Repeat("-", 28)+"< snapp >"+strings.Repeat("-", 29))
	logglinjer = strings.ReplaceAll(logglinjer, "\r", "")
	logglinjer = strings.Trim(logglinjer, "* \n\t")

	// Parse event date from email header
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	// Try to extract a more precise date from the summary
	if summary != "" && eventDate != nil {
		matches := dateFinder.FindStringSubmatch(summary)
		if len(matches) > 0 {
			// Extract named groups
			monthIdx := dateFinder.SubexpIndex("month")
			dayIdx := dateFinder.SubexpIndex("day")
			timeIdx := dateFinder.SubexpIndex("time")

			if monthIdx > 0 && dayIdx > 0 && timeIdx > 0 {
				month := matches[monthIdx]
				day := matches[dayIdx]
				timeStr := matches[timeIdx]
				year := fmt.Sprintf("%d", eventDate.Year())

				// Construct date string and parse it
				rawDate := fmt.Sprintf("%s %s %s %s:00", day, month, year, timeStr)
				parsedDate := email.ParseDate(rawDate)
				if parsedDate != nil {
					eventDate = parsedDate
				}
			}
		}
	}

	// Create event
	event := events.NewEvent("telenor")
	event.EventTypes = []events.EventType{events.NewCompromisedAccount(userPassword)}
	event.EventDate = eventDate

	// Add identification requirement
	event.AddRequirement("identification", events.NewAndRequirement([]interface{}{
		events.NewCompromisedAccount(userPassword),
	}))

	// Add evidence
	evidence := &events.Evidence{}
	if summary != "" {
		evidence.AddEvidence(events.UrlStore{
			Description: "summary",
			URL:         summary,
		})
	}
	if lookup != "" {
		evidence.AddEvidence(events.UrlStore{
			Description: "geo_ip",
			URL:         lookup,
		})
	}

	// Parse log lines
	if logglinjer != "" {
		logs := strings.Split(logglinjer, "\n\n")
		for _, log := range logs {
			log = strings.TrimSpace(log)
			if log == "" {
				continue
			}

			// Find first colon to split key and value
			colonIdx := strings.Index(log, ":")
			if colonIdx > 0 {
				key := log[:colonIdx]
				value := strings.TrimSpace(log[colonIdx+1:])
				evidence.AddEvidence(events.UrlStore{
					Description: key,
					URL:         value,
				})
			}
		}
	}

	event.AddEventDetail(evidence)

	return []*events.Event{event}, nil
}

// getDataWithoutFirst joins lines excluding the first one
func getDataWithoutFirst(lines []string) string {
	if len(lines) <= 1 {
		return ""
	}
	return strings.Join(lines[1:], "\n")
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
