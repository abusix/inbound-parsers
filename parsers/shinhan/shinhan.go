package shinhan

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

type rowData struct {
	date    string
	srcIP   string
	srcPort string
	dstIP   string
	dstPort string
	proto   string
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Parse HTML to text using goquery (similar to BeautifulSoup)
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return nil, common.NewParserError("failed to parse HTML: " + err.Error())
	}

	// Get the text content
	bodyText := doc.Text()

	// Split by separator
	parts := strings.Split(bodyText, "===================================")
	if len(parts) < 2 {
		return nil, common.NewParserError("separator '===================================' not found")
	}

	// Extract the table section (part after first separator)
	tableText := parts[1]

	// Split into lines and filter out empty ones
	lines := strings.Split(tableText, "\n")
	var table []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			table = append(table, trimmed)
		}
	}

	if len(table) == 0 {
		return nil, common.NewParserError("no table data found")
	}

	// Parse the header to determine format
	header := strings.Split(table[0], "   ")
	var mappedRows []rowData

	// Clean up header elements
	for i := range header {
		header[i] = strings.TrimSpace(header[i])
	}
	header = filterEmpty(header)

	// Determine format based on header
	// Python: row_to_dict(table[i : i + 7]) means pass slice of 7 elements from table
	// where table is the flat list of all non-empty lines
	if sliceEqual(header, []string{"No", "Detect Time", "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol"}) {
		// Format 1: 7 elements per row
		// Python: row_to_dict = row_mapper(1, 2, 3, 4, 5, 6)
		// This means: date=row[1], src_ip=row[2], src_port=row[3], dst_ip=row[4], dst_port=row[5], proto=row[6]
		for i := 1; i < len(table); i += 7 {
			if i+6 >= len(table) {
				break
			}
			row := rowData{
				date:    cleanWhitespace(table[i+1]),
				srcIP:   table[i+2],
				srcPort: table[i+3],
				dstIP:   table[i+4],
				dstPort: table[i+5],
				proto:   table[i+6],
			}
			mappedRows = append(mappedRows, row)
		}
	} else if sliceEqual(header, []string{"Manager", "Receipt Time"}) {
		// Format 2: 6 elements per row with date parsing
		// Python: row_to_dict = row_mapper(0, 1, 2, 3, 4, 5, date_format='%b %d %Y %H:%M:%S')
		// This means: date=row[0], src_ip=row[1], src_port=row[2], dst_ip=row[3], dst_port=row[4], proto=row[5]
		// Note: The header rows are at indices 0,1 so data starts at index 2 (skipping 2 header lines)
		// But Python does range(6, len(table), 6) which starts at index 6
		for i := 6; i < len(table); i += 6 {
			if i+5 >= len(table) {
				break
			}
			// Date is all in one element already in the format "Jan 02 2006 15:04:05"
			parsed, err := parseShortDate(table[i])
			if err == nil {
				row := rowData{
					date:    parsed,
					srcIP:   table[i+1],
					srcPort: table[i+2],
					dstIP:   table[i+3],
					dstPort: table[i+4],
					proto:   table[i+5],
				}
				mappedRows = append(mappedRows, row)
			}
		}
	} else if sliceEqual(header, []string{"Agent", "Receipt Time"}) {
		// Format 3: 5 elements per row (no protocol)
		// Python: row_to_dict = row_mapper(0, 1, 2, 3, 4, None, date_format='%b %d %Y %H:%M:%S')
		// This means: date=row[0], src_ip=row[1], src_port=row[2], dst_ip=row[3], dst_port=row[4], proto=None
		for i := 5; i < len(table); i += 5 {
			if i+4 >= len(table) {
				break
			}
			parsed, err := parseShortDate(table[i])
			if err == nil {
				row := rowData{
					date:    parsed,
					srcIP:   table[i+1],
					srcPort: table[i+2],
					dstIP:   table[i+3],
					dstPort: table[i+4],
					proto:   "",
				}
				mappedRows = append(mappedRows, row)
			}
		}
	} else {
		return nil, common.NewParserError(fmt.Sprintf("unknown table format with header: %v", header))
	}

	// Extract timezone offset
	timedelta := common.FindStringWithoutMarkers(bodyText, "GMT+", ")")

	var eventsList []*events.Event

	for _, row := range mappedRows {
		event := events.NewEvent("shinhan")
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}

		// Set event date with timezone
		if timedelta != "" {
			dateWithTZ := fmt.Sprintf("%s+0%s", row.date, timedelta)
			event.EventDate = email.ParseDate(dateWithTZ)
		} else {
			event.EventDate = email.ParseDate(row.date)
		}

		// Set source IP
		if validIP := common.IsIP(row.srcIP); validIP != "" {
			event.IP = validIP
		}

		// Set source port
		if port, err := strconv.Atoi(row.srcPort); err == nil {
			event.Port = port
		}

		// Add target details
		target := &events.Target{}
		if validIP := common.IsIP(row.dstIP); validIP != "" {
			target.IP = validIP
		}
		if row.dstPort != "" {
			target.Port = row.dstPort
		}
		if target.IP != "" || target.Port != "" {
			event.AddEventDetail(target)
		}

		// Add protocol
		if row.proto != "" {
			event.AddEventDetail(&events.TransportProtocol{
				Protocol: row.proto,
			})
		}

		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no events created")
	}

	return eventsList, nil
}

// cleanWhitespace replaces multiple whitespace with single space
func cleanWhitespace(s string) string {
	re := regexp.MustCompile(`\s+`)
	return re.ReplaceAllString(s, " ")
}

// filterEmpty removes empty strings from a slice
func filterEmpty(slice []string) []string {
	var result []string
	for _, s := range slice {
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}

// sliceEqual checks if two string slices are equal
func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// parseShortDate parses dates like "Jan 02 2006 15:04:05"
func parseShortDate(dateStr string) (string, error) {
	// Format: "Jan 02 2006 15:04:05"
	t, err := time.Parse("Jan 02 2006 15:04:05", dateStr)
	if err != nil {
		return "", err
	}
	// Return as RFC3339-like format that email.ParseDate can handle
	return t.Format("2 Jan 2006 15:04:05"), nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
