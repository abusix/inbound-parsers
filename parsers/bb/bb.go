package bb

import (
	"fmt"
	"regexp"
	"strconv"
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
	subject, _ := common.GetSubject(serializedEmail, false)

	// Get from address
	var fromAddr string
	if serializedEmail.Headers != nil {
		if from, ok := serializedEmail.Headers["from"]; ok && len(from) > 0 {
			fromAddr = from[0]
		}
	}

	// Strip HTML and normalize text
	bodyText := stripHTML(body)
	bodyText = normalizeText(bodyText)

	// Check if this is a phishing report from abuse@bb.com.br
	if fromAddr == "abuse@bb.com.br" {
		return parsePhishingReport(serializedEmail, bodyText)
	}

	// Otherwise, parse as bot/login attack report
	return parseBotLoginReport(serializedEmail, bodyText, subject)
}

// stripHTML removes HTML tags and normalizes whitespace
func stripHTML(html string) string {
	// Replace br/div/span tags with newlines
	html = regexp.MustCompile(`(?i)<br[^>]*>`).ReplaceAllString(html, "\n")
	html = regexp.MustCompile(`(?i)<div[^>]*>`).ReplaceAllString(html, "\n")
	html = regexp.MustCompile(`(?i)<span[^>]*>`).ReplaceAllString(html, "\n")

	// Remove all other HTML tags
	html = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(html, "")

	return html
}

// normalizeText performs Unicode normalization (NFKD) approximation
func normalizeText(text string) string {
	// Go's unicode normalization is in golang.org/x/text/unicode/norm
	// For simplicity, we'll just clean up the text
	text = strings.ReplaceAll(text, "\r", "\n")
	return text
}

// parsePhishingReport handles reports from abuse@bb.com.br
func parsePhishingReport(serializedEmail *email.SerializedEmail, bodyText string) ([]*events.Event, error) {
	event := events.NewEvent("bb")

	// Get event date from headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		event.EventDate = email.ParseDate(dateHeader[0])
	}

	// Extract phishing URL - find "://" and extract URL around it
	index := strings.Index(bodyText, "://")
	if index == -1 {
		return nil, fmt.Errorf("no URL found in phishing report")
	}

	// Find start of URL (after space, newline, or carriage return)
	indexURLStart := 0
	spaceIdx := strings.LastIndex(bodyText[:index], " ")
	newlineIdx := strings.LastIndex(bodyText[:index], "\n")
	crIdx := strings.LastIndex(bodyText[:index], "\r")

	indexURLStart = max(spaceIdx, newlineIdx, crIdx) + 1

	// Find end of URL (next space)
	indexURLEnd := strings.Index(bodyText[index:], " ")
	if indexURLEnd == -1 {
		indexURLEnd = len(bodyText)
	} else {
		indexURLEnd += index
	}

	phishingURL := bodyText[indexURLStart:indexURLEnd]
	phishingURL = strings.TrimSpace(phishingURL)

	event.URL = phishingURL
	event.EventTypes = []events.EventType{events.NewPhishing()}

	return []*events.Event{event}, nil
}

// parseBotLoginReport handles bot and login attack reports
func parseBotLoginReport(serializedEmail *email.SerializedEmail, bodyText, subject string) ([]*events.Event, error) {
	var evts []*events.Event

	// Extract target IP
	targetIP := extractTargetIP(bodyText)

	// Check if this is a bot report (possibleurlabuse in subject)
	subjectLower := strings.ToLower(strings.ReplaceAll(subject, " ", ""))
	if strings.Contains(subjectLower, "possibleurlabuse") {
		// Extract source IP
		sourceIP := common.FindStringWithoutMarkers(bodyText, "Source IP ", "")
		sourceIP = strings.TrimSpace(sourceIP)

		// Parse table data
		tableRows := getTableAsDict(serializedEmail, bodyText)

		for _, row := range tableRows {
			event := events.NewEvent("bb")
			event.EventDate = email.ParseDate(row["date"])
			event.IP = sourceIP

			// Add target details
			target := row["target_ip"]
			if target == "" {
				target = targetIP
			}
			if target != "" && !strings.Contains(target, ".XX") {
				event.AddEventDetail(&events.Target{
					IP:   target,
					Port: row["target_port"],
				})
			}

			event.EventTypes = []events.EventType{events.NewBot("")}

			// Handle source port - may contain "/" for multiple ports
			sourcePort := row["source_port"]
			if strings.Contains(sourcePort, "/") {
				ports := strings.Split(sourcePort, "/")
				event.Port = parsePort(ports[0])
				evts = append(evts, event)

				// Create second event for second port
				event2 := events.NewEvent("bb")
				event2.EventDate = event.EventDate
				event2.IP = sourceIP
				event2.Port = parsePort(ports[1])
				if target != "" && !strings.Contains(target, ".XX") {
					event2.AddEventDetail(&events.Target{
						IP:   target,
						Port: row["target_port"],
					})
				}
				event2.EventTypes = []events.EventType{events.NewBot("")}
				evts = append(evts, event2)
			} else {
				event.Port = parsePort(sourcePort)
				evts = append(evts, event)
			}
		}
	} else {
		// Login attack report - source IP from subject
		sourceIP := subject

		// Parse table data
		tableRows := getTableAsDict(serializedEmail, bodyText)

		for _, row := range tableRows {
			event := events.NewEvent("bb")
			event.EventDate = email.ParseDate(row["date"])

			// Use row source IP if available, otherwise use subject
			if row["source_ip"] != "" {
				event.IP = row["source_ip"]
			} else {
				event.IP = sourceIP
			}
			event.Port = parsePort(row["source_port"])

			// Add target details
			target := row["target_ip"]
			if target == "" {
				target = targetIP
			}
			if target != "" && !strings.Contains(target, ".XX") {
				event.AddEventDetail(&events.Target{
					IP:   target,
					Port: row["target_port"],
				})
			} else {
				event.AddEventDetail(&events.Target{
					Port: row["target_port"],
				})
			}

			event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
			evts = append(evts, event)
		}

		// If no events created from table, create one from target IP and port
		if len(evts) == 0 {
			event := events.NewEvent("bb")

			if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
				event.EventDate = email.ParseDate(dateHeader[0])
			}

			event.IP = sourceIP

			// Try to extract port
			portRegex := regexp.MustCompile(`Destination Port:\s*(\d+)`)
			portMatches := portRegex.FindStringSubmatch(bodyText)
			var port string
			if len(portMatches) > 1 {
				port = portMatches[1]
			}

			event.AddEventDetail(&events.Target{
				IP:   targetIP,
				Port: port,
			})
			event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

			evts = append(evts, event)
		}
	}

	return evts, nil
}

// extractTargetIP extracts the target/destination IP from the body
func extractTargetIP(bodyText string) string {
	// Try "Destination IP:" or "Destination:" pattern
	destRegex := regexp.MustCompile(`Destination(?: IP)?:\s*((?:[\dX]*\.)*[\dXx]*)`)
	matches := destRegex.FindStringSubmatch(bodyText)

	var targetIP string
	if len(matches) > 1 {
		targetIP = matches[1]
	} else {
		// Try Portuguese "IP de destino:"
		targetIP = common.FindStringWithoutMarkers(bodyText, "IP de destino:", "")
	}

	// Filter out .XX patterns
	if strings.Contains(targetIP, ".XX") {
		return ""
	}

	return strings.TrimSpace(targetIP)
}

// getTableAsDict extracts table data from the email body
func getTableAsDict(serializedEmail *email.SerializedEmail, bodyText string) []map[string]string {
	var results []map[string]string

	// Extract data section
	data := extractData(serializedEmail, bodyText)
	if data == "" {
		return results
	}

	// Split into lines and skip first 2 lines (headers)
	lines := strings.Split(data, "\n")
	if len(lines) <= 2 {
		return results
	}

	sourceTable := lines[2:]

	for _, row := range sourceTable {
		row = strings.TrimSpace(row)
		if row == "" {
			continue
		}

		values := cleanUpRowAndSplit(row)
		if len(values) == 0 {
			continue
		}

		// Parse different row formats
		var rowData map[string]string

		switch len(values) {
		case 5:
			// [date, source_ip, source_port, target_ip, target_port]
			rowData = map[string]string{
				"date":        values[0],
				"source_ip":   values[1],
				"source_port": values[2],
				"target_ip":   values[3],
				"target_port": values[4],
			}
		case 3:
			// [date, source_part, target_part]
			sourceParts := strings.Split(values[1], "/")
			targetParts := strings.Split(values[2], "/")

			var sourceIP, sourcePort, targetIP, targetPort string
			if len(sourceParts) >= 2 {
				sourceIP = sourceParts[0]
				sourcePort = sourceParts[1]
			}
			if len(targetParts) >= 2 {
				targetIP = targetParts[0]
				targetPort = targetParts[1]
			}

			rowData = map[string]string{
				"date":        values[0],
				"source_ip":   sourceIP,
				"source_port": sourcePort,
				"target_ip":   targetIP,
				"target_port": targetPort,
			}
		case 4:
			// [date, source_ip, source_port, target_port]
			rowData = map[string]string{
				"date":        values[0],
				"source_ip":   values[1],
				"source_port": values[2],
				"target_ip":   "",
				"target_port": values[3],
			}
		default:
			// Unknown format, skip
			continue
		}

		results = append(results, rowData)
	}

	return results
}

// cleanUpRowAndSplit cleans up a row and splits it by multiple spaces
func cleanUpRowAndSplit(row string) []string {
	row = strings.ReplaceAll(row, "\n", "")
	row = strings.ReplaceAll(row, "\r", "")

	// Split by multiple spaces (2 or more)
	values := regexp.MustCompile(`\s{2,}`).Split(row, -1)

	// Filter empty values and trim
	var result []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			result = append(result, v)
		}
	}

	return result
}

// extractData extracts the data section from the email body
func extractData(serializedEmail *email.SerializedEmail, bodyText string) string {
	body, _ := common.GetBody(serializedEmail, true)

	// Strip HTML and normalize
	body = stripHTML(body)
	body = normalizeText(body)

	// Find section between "-----" and "We kindly request"
	startIdx := strings.Index(body, "-----")
	endIdx := strings.Index(body, "We kindly request")

	if startIdx == -1 || endIdx == -1 || startIdx >= endIdx {
		return ""
	}

	body = body[startIdx:endIdx]
	body = strings.TrimSpace(body)

	// Clean up multiple newlines
	if strings.Contains(body, "\n\n") {
		body = strings.ReplaceAll(body, "\n\n\n", "\n")
		body = strings.ReplaceAll(body, "\n\n", "\n")
	}

	return body
}

// max returns the maximum of integers
func max(vals ...int) int {
	if len(vals) == 0 {
		return 0
	}
	maxVal := vals[0]
	for _, v := range vals[1:] {
		if v > maxVal {
			maxVal = v
		}
	}
	return maxVal
}

// parsePort converts a port string to int, returns 0 if invalid
func parsePort(portStr string) int {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return port
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
