package baysidecorp

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

	// Extract reporter information
	reporterName := strings.TrimSpace(strings.Trim(common.FindStringWithoutMarkers(body, "s Name:", ""), " *"))
	reporterEmailRaw := strings.TrimSpace(strings.Trim(common.FindStringWithoutMarkers(body, "s Email Address:", ""), " *"))

	// Extract first word (email address) from email field
	reporterEmail := ""
	if emailFields := strings.Fields(reporterEmailRaw); len(emailFields) > 0 {
		reporterEmail = emailFields[0]
	}

	reporterCompanyName := strings.TrimSpace(strings.Trim(common.FindStringWithoutMarkers(body, "s Company Name:", ""), " *"))
	reporterAddress := strings.TrimSpace(strings.Trim(common.FindStringWithoutMarkers(body, "s Address:", ""), " *"))

	// Create reporter organization
	reporter := &events.Organisation{
		Name:         "reporter",
		ContactName:  reporterName,
		ContactEmail: reporterEmail,
		Organisation: reporterCompanyName,
		Address:      reporterAddress,
	}

	// Determine event type from subject
	var eventType events.EventType
	if strings.Contains(subjectLower, "copyright") {
		eventType = &events.Copyright{}
	} else {
		return nil, common.NewNewTypeError(subjectLower)
	}

	// Extract URLs between "URLs:" and "Dear Sir or Madam"
	urlsBlock := common.FindStringWithoutMarkers(body, "URLs:", "Dear Sir or Madam")
	urlPattern := regexp.MustCompile(`http.*`)
	urls := urlPattern.FindAllString(urlsBlock, -1)

	// Get event date from email headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	// Create one event per URL
	var eventList []*events.Event
	for _, url := range urls {
		event := events.NewEvent("baysidecorp")
		event.EventTypes = []events.EventType{eventType}
		event.EventDate = eventDate
		event.URL = strings.TrimSpace(url)
		event.AddEventDetail(reporter)

		eventList = append(eventList, event)
	}

	if len(eventList) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return eventList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
