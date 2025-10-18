package mm_moneygram

import (
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
	bodyLower := strings.ToLower(body)

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	// Get event date from email headers
	var eventDate *time.Time
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Create trademark event type
	trademark := &events.Trademark{
		BaseEventType: events.BaseEventType{
			Name: "trademark",
			Type: "trademark",
		},
		TrademarkOwner: "MoneyGram International, Inc.",
	}

	// Extract URLs from body
	var urls []string

	// First attempt: extract between "have the appearance of children :" and "mgi represents"
	urlSection := common.FindStringWithoutMarkers(bodyLower, "have the appearance of children :", "mgi represents")
	if urlSection != "" {
		lines := strings.Split(urlSection, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if common.IsURL(line) {
				urls = append(urls, line)
			}
		}
	}

	// Second attempt if no URLs found: extract between "tobacco related products […]." and "mgi represents"
	if len(urls) == 0 {
		urlSection = common.FindStringWithoutMarkers(bodyLower, "tobacco related products […].", "mgi represents")
		if urlSection != "" {
			lines := strings.Split(urlSection, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if common.IsURL(line) {
					urls = append(urls, line)
				}
			}
		}
	}

	// Third attempt if no URLs found: extract from subject between "moneygram marks -" and "[ecin:"
	if len(urls) == 0 {
		url := common.FindStringWithoutMarkers(subjectLower, "moneygram marks -", "[ecin:")
		url = strings.TrimSpace(url)
		if url != "" {
			urls = append(urls, url)
		}
	}

	// Create events for each URL found
	var result []*events.Event
	for _, url := range urls {
		event := events.NewEvent("mm_moneygram")
		event.URL = url
		event.EventDate = eventDate
		event.EventTypes = []events.EventType{trademark}
		result = append(result, event)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
