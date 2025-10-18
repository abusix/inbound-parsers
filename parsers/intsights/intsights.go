package intsights

import (
	"strings"

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

	// Extract copyright owner from "legal representatives of {owner} ("
	copyrightOwner := strings.TrimSpace(common.FindStringWithoutMarkers(body, "legal representatives of", "("))
	if copyrightOwner == "" {
		return nil, common.NewParserError("copyright owner not found")
	}

	// Extract official URL from "{copyright_owner} ({official_url})"
	officialURL := common.FindStringWithoutMarkers(body, copyrightOwner+" (", ")")

	// Extract URL from "on your servers: {url},"
	// URL is built as "http" + the part after "http" in the cleaned URL
	urlPart := common.CleanURL(common.FindStringWithoutMarkers(body, "on your servers:", ","))
	url := ""
	if strings.Contains(urlPart, "http") {
		parts := strings.Split(urlPart, "http")
		if len(parts) > 1 {
			url = "http" + parts[1]
		}
	}

	// Extract IPs from "carrying IP number {ip1}, {ip2}, ..."
	ipsString := common.FindStringWithoutMarkers(body, "carrying IP number", "")
	ipEntries := strings.Split(ipsString, ",")

	var resultEvents []*events.Event

	for _, entry := range ipEntries {
		if ip := common.ExtractOneIP(entry); ip != "" {
			event := events.NewEvent("intsights")

			// Set event date from headers['date'][0]
			if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
				event.EventDate = email.ParseDate(dateHeaders[0])
			}

			// Set event type as Copyright with owner and official URL
			event.EventTypes = []events.EventType{events.NewCopyright("", copyrightOwner, "")}

			// Add official_url to the Copyright event type if available
			if officialURL != "" {
				if copyrightType, ok := event.EventTypes[0].(*events.Copyright); ok {
					copyrightType.OfficialURL = officialURL
				}
			}

			event.URL = url
			event.IP = ip

			resultEvents = append(resultEvents, event)
		}
	}

	if len(resultEvents) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return resultEvents, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
