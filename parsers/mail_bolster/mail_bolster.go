package mail_bolster

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	// PHISH_FINDER = re.compile(r'(hxxp.*)\s*is\s*hosting\s*(?:<b>)?\s*(.*)\s*(?:</b>)?\s*phish')
	phishFinder = regexp.MustCompile(`(hxxp.*)\s*is\s*hosting\s*(?:<b>)?\s*(.*)\s*(?:</b>)?\s*phish`)
)

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// try: url, target_brand = PHISH_FINDER.search(body).groups()
	matches := phishFinder.FindStringSubmatch(body)
	if matches == nil || len(matches) < 3 {
		return nil, common.NewParserError("url and target brand could not be found.")
	}

	url := matches[1]
	targetBrand := matches[2]

	// target_brand = target_brand.replace('<b>', '').replace('</b>', '').strip()
	targetBrand = strings.ReplaceAll(targetBrand, "<b>", "")
	targetBrand = strings.ReplaceAll(targetBrand, "</b>", "")
	targetBrand = strings.TrimSpace(targetBrand)

	// url = clean_url(url)
	url = common.CleanURL(url)

	// event = Event('mail_bolster')
	event := events.NewEvent("mail_bolster")

	// event.event_date = serialized_email['headers']['date'][0]
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// event.url = url
	event.URL = url

	// event.add_event_detail(Target(brand=target_brand))
	event.AddEventDetail(&events.Target{
		Brand: targetBrand,
	})

	// event.event_types = Phishing(phishing_url=url)
	phishing := events.NewPhishing()
	event.EventTypes = []events.EventType{phishing}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
