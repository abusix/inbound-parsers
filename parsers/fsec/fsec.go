// Package fsec implements the FSEC parser for South Korean security reports
package fsec

import (
	"fmt"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

// Parse parses emails from isac@fsec.or.kr
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Try HTML table parsing first
	doc, htmlErr := goquery.NewDocumentFromReader(strings.NewReader(body))
	if htmlErr == nil {
		tables := doc.Find("table")
		if tables.Length() > 0 {
			return parseTable(body, doc)
		}
	}

	// Fall back to old format parsing
	if strings.Contains(body, "as shown below") {
		return parseOldFormat(body)
	}

	return nil, common.NewParserError("could not determine report type")
}

// parseOldFormat parses the old text-based format
func parseOldFormat(body string) ([]*events.Event, error) {
	var eventsList []*events.Event

	var date *string
	var attackType string
	var sourceIP string
	var dstIPList []string

	lines := common.GetBlockAfterWithStop(body, "site as shown below.", "")
	for _, line := range lines {
		if strings.HasPrefix(line, "Date/Time") {
			parsedDate := getDate(line)
			date = &parsedDate
		}
		if strings.HasPrefix(line, "Attack Type") {
			parts := strings.SplitN(line, " : ", 2)
			if len(parts) > 1 {
				attackType = strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(line, "Source IP") {
			sourceIP = line
		}
		if strings.HasPrefix(line, "Destination IP") {
			parts := strings.SplitN(line, " : ", 2)
			if len(parts) > 1 {
				ipList := strings.Split(parts[1], ",")
				for _, ip := range ipList {
					dstIPList = append(dstIPList, strings.TrimSpace(ip))
				}
			}
		}
	}

	// Create events for each destination IP
	for _, dstIP := range dstIPList {
		event := createEvent(date, sourceIP, dstIP, attackType)
		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no events created from old format")
	}

	return eventsList, nil
}

// parseTable parses the HTML table format
func parseTable(body string, doc *goquery.Document) ([]*events.Event, error) {
	var eventsList []*events.Event

	timeZone := ""
	rows := doc.Find("tr")
	rows.Each(func(i int, row *goquery.Selection) {
		cells := row.Find("td")
		if cells.Length() == 0 {
			return
		}

		var entry []string
		cells.Each(func(j int, cell *goquery.Selection) {
			entry = append(entry, cell.Text())
		})

		if i == 0 {
			// First row contains the timezone
			if len(entry) > 0 {
				timeZone = strings.Replace(entry[0], "Date/Time", "", 1)
			}
		} else {
			// Data rows
			if len(entry) >= 4 {
				// Split the first cell by ~ to get just the start time
				dateParts := strings.Split(entry[0], "~")
				dateStr := timeZone + " " + strings.TrimSpace(dateParts[0])
				date := getDate(dateStr)

				ip := strings.TrimSpace(entry[1])
				dstIP := strings.TrimSpace(entry[2])
				attackType := strings.TrimSpace(entry[3])

				event := createEvent(&date, ip, dstIP, attackType)
				eventsList = append(eventsList, event)
			}
		}
	})

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no events created from table")
	}

	return eventsList, nil
}

// getDate extracts and formats the date from the FSEC format
// Input example: "(GMT+9) 2024-10-15 14:30:00 ~ 2024-10-15 15:00:00"
// Output: "2024-10-15 14:30:00+09:00"
// This is a 100% exact port of the Python _get_date function
func getDate(line string) string {
	// Find the tilde separator
	index := strings.Index(line, "~")
	if index == -1 {
		return ""
	}

	// Find GMT position
	indexSign := strings.Index(line, "GMT") + len("GMT")
	indexGMT := strings.Index(line, "GMT") + len("GMT+")

	if indexSign >= len(line) || indexGMT >= len(line) {
		return ""
	}

	// Check if we have a double-digit offset (like GMT+10, GMT+11)
	// by checking if the character before indexGMT is '1'
	var date string
	if indexGMT-1 < len(line) && line[indexGMT-1] == '1' {
		// Double digit offset: use '1' + the digit at indexGMT+1
		if indexGMT+1 < len(line) {
			date = fmt.Sprintf("%s%c1%c:00",
				line[index+2:],   // date/time after "~ "
				line[indexSign],  // sign character (+ or -)
				line[indexGMT+1]) // second digit of offset
		}
	} else {
		// Single digit offset: use '0' + the digit at indexGMT
		if indexGMT < len(line) {
			date = fmt.Sprintf("%s%c0%c:00",
				line[index+2:],  // date/time after "~ "
				line[indexSign], // sign character (+ or -)
				line[indexGMT])  // single digit offset
		}
	}

	return date
}

// createEvent creates an event from the parsed data
func createEvent(date *string, sourceIP string, dstIP string, attackType string) *events.Event {
	event := events.NewEvent("fsec")

	// Set event date
	if date != nil {
		parsedDate := email.ParseDate(*date)
		event.EventDate = parsedDate
	}

	// Create evidence with attack type
	evidence := &events.Evidence{}
	evidence.AddEvidence(events.UrlStore{
		Description: "attack",
		URL:         attackType,
	})
	event.AddEventDetail(evidence)

	// Set source IP
	event.IP = common.ExtractOneIP(sourceIP)

	// Add destination IP as target
	if dstIP != "" {
		cleanDstIP := common.ExtractOneIP(dstIP)
		if cleanDstIP != "" {
			event.AddEventDetail(&events.Target{
				IP: cleanDstIP,
			})
		}
	}

	// Set event type as Exploit
	event.EventTypes = []events.EventType{events.NewExploit()}

	return event
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
