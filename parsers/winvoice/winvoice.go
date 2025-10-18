// Package winvoice implements the winvoice parser
// This is a 100% exact Go translation of Python's winvoice.py
package winvoice

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the parser
type Parser struct{}

// Match returns true if the email is from @winvoice.com
func Match(serializedEmail *email.SerializedEmail, fromAddr string) bool {
	if fromAddr == "" || !strings.Contains(fromAddr, "@winvoice.com") {
		return false
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return false
	}

	subjectLower := strings.ToLower(subject)
	if strings.Contains(subjectLower, "re:") {
		return false
	}

	return true
}

// Parse processes the winvoice abuse email
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Replace space+\r\n with space
	body = strings.ReplaceAll(body, " \r\n", " ")

	logs := fieldsToDict(body)

	// Parse event details
	eventTemplate := events.NewEvent("winvoice")

	// Get date from headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
			eventTemplate.EventDate = parsedDate
		}
	}

	var result []*events.Event

	if len(logs) > 0 {
		for _, line := range logs {
			event := copyEvent(eventTemplate)

			// Set IP
			if cIP, ok := line["c-ip"]; ok {
				event.IP = cIP
			}

			// Set port
			if cPort, ok := line["c-port"]; ok {
				if portInt := 0; cPort != "" {
					if _, err := fmt.Sscanf(cPort, "%d", &portInt); err == nil {
						event.Port = portInt
					}
				}
			}

			// Add target if s-ip is valid
			if sIP, ok := line["s-ip"]; ok && common.IsIP(sIP) != "" {
				target := &events.Target{
					IP: sIP,
				}
				if sPort, ok := line["s-port"]; ok {
					target.Port = sPort
				}
				event.AddEventDetail(target)
			}

			// Parse dates
			if dateVal, hasDate := line["date"]; hasDate && dateVal != "" {
				if timeVal, hasTime := line["time"]; hasTime && timeVal != "" {
					dateTimeStr := dateVal + timeVal
					if parsedDate := email.ParseDate(dateTimeStr); parsedDate != nil {
						event.EventDate = parsedDate
					}
				} else {
					if parsedDate := email.ParseDate(dateVal); parsedDate != nil {
						event.EventDate = parsedDate
					}
				}
			}

			// Get event type from subject
			eventType, err := getType(subjectLower)
			if err != nil {
				return nil, err
			}
			event.EventTypes = []events.EventType{eventType}

			result = append(result, event)
		}
	} else {
		// No logs found, parse from subject
		eventTemplate.IP = subject
		eventType, err := getType(subjectLower)
		if err != nil {
			return nil, err
		}
		eventTemplate.EventTypes = []events.EventType{eventType}

		// Try to extract date from body
		dateSearch := regexp.MustCompile(`--- (.+?) ---`).FindStringSubmatch(body)
		if len(dateSearch) > 1 {
			if parsedDate := email.ParseDate(dateSearch[1]); parsedDate != nil {
				eventTemplate.EventDate = parsedDate
			}
		}

		result = append(result, eventTemplate)
	}

	return result, nil
}

// fieldsToDict parses #Fields: format from body
func fieldsToDict(body string) []map[string]string {
	bodyLines := strings.Split(body, "\n")
	var logs []map[string]string

	if !strings.Contains(body, "#Fields:") {
		return logs
	}

	fieldsIdx := 0
	// Get the last occurrence of #Fields:
	for index, line := range bodyLines {
		if strings.HasPrefix(line, "#Fields:") {
			fieldsIdx = index
		}
	}

	// Extract field names
	fieldsLine := bodyLines[fieldsIdx]
	fieldsLine = strings.TrimPrefix(fieldsLine, "#Fields: ")
	fields := strings.Split(fieldsLine, " ")

	// Extract values (non-empty lines after fields)
	var values []string
	for i := fieldsIdx + 1; i < len(bodyLines); i++ {
		line := bodyLines[i]
		if line != "" {
			values = append(values, line)
		}
	}

	// Create dict for each line
	for _, line := range values {
		parts := strings.Split(line, " ")
		logEntry := make(map[string]string)

		// Zip fields and parts
		for i, field := range fields {
			if i < len(parts) {
				logEntry[field] = parts[i]
			}
		}

		logs = append(logs, logEntry)
	}

	return logs
}

// getType determines the event type based on subject
func getType(subject string) (events.EventType, error) {
	// Check for LoginAttack
	loginAttackKeywords := []string{
		"authentication failed",
		"imap",
		"pop3",
		"smtp",
		"index.php",
		"admin",
		"env",
		"login",
		"wp-cc",
		"auth.owa",
		"config",
	}

	for _, keyword := range loginAttackKeywords {
		if strings.Contains(subject, keyword) {
			return events.NewLoginAttack("", ""), nil
		}
	}

	// Check for Exploit
	exploitKeywords := []string{
		"hello+world",
		"python-requests",
		"connect",
		"curl",
		"phpinfo",
		"wget",
		"wordpress",
		"hnap1",
		"ds_store",
		"manager/html",
		"aws/credentials",
		"+cscoe+/logon.html",
		"data/nextcloud.log",
		"application.properties",
		"_profiler/phpinfo",
		"data/owncloud.log",
	}

	for _, keyword := range exploitKeywords {
		if strings.Contains(subject, keyword) {
			return events.NewExploit(), nil
		}
	}

	if strings.Contains(subject, "attacks from multiple linode ips") {
		return events.NewExploit(), nil
	}

	// Unknown type
	return nil, common.NewNewTypeError(subject)
}

// copyEvent creates a shallow copy of an event
func copyEvent(template *events.Event) *events.Event {
	event := *template
	// Deep copy slices and maps
	if template.EventTypes != nil {
		event.EventTypes = make([]events.EventType, len(template.EventTypes))
		copy(event.EventTypes, template.EventTypes)
	}
	if template.EventDetails != nil {
		event.EventDetails = make([]events.EventDetail, len(template.EventDetails))
		copy(event.EventDetails, template.EventDetails)
	}
	if template.Headers != nil {
		event.Headers = make(map[string]interface{}, len(template.Headers))
		for k, v := range template.Headers {
			event.Headers[k] = v
		}
	}
	if template.Requirements != nil {
		event.Requirements = make(map[string]events.Requirement, len(template.Requirements))
		for k, v := range template.Requirements {
			event.Requirements[k] = v
		}
	}
	return &event
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
