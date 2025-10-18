package dnainternet

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the dnainternet parser
type Parser struct{}

// NewParser creates a new dnainternet parser
func NewParser() *Parser {
	return &Parser{}
}

// extractDateFromLine extracts the date from a line in the format: [ auto-generated abuse report (date) ]
func extractDateFromLine(line string) string {
	// Split by '(' to get the date part
	parts := strings.Split(line, "(")
	if len(parts) < 2 {
		return ""
	}

	// Get the part after '('
	datePart := parts[1]
	if len(datePart) <= 2 {
		return ""
	}

	// Split by ')' to remove the closing paren
	parts = strings.Split(datePart, ")")
	if len(parts) > 0 {
		return parts[0]
	}

	return ""
}

// parseSpamType parses spam-type abuse reports
func parseSpamType(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	event := events.NewEvent("dnainternet")

	// Get event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	bodyLower := strings.ToLower(body)

	foundIP := false
	foundEventType := false

	for _, line := range strings.Split(bodyLower, "\n") {
		line = strings.TrimSpace(line)

		// Extract date from auto-generated abuse report line
		if strings.HasPrefix(line, "[ auto-generated abuse report") {
			date := extractDateFromLine(line)
			if date == "" {
				return nil, common.NewParserError("Date not found")
			}

			// Convert date format: 'tue jun  7 00:01:30 eest 2022' to 'Thu Jun 7 00:01:30 EEST 2022'
			// Normalize whitespace first
			re := regexp.MustCompile(`\s+`)
			date = re.ReplaceAllString(date, " ")

			// Split date into parts
			parts := strings.Split(date, " ")
			if len(parts) >= 5 {
				// Capitalize day, month, day-of-month (first 3 parts)
				datePart := make([]string, 0, 3)
				for i := 0; i < 3 && i < len(parts); i++ {
					datePart = append(datePart, strings.Title(strings.ToLower(parts[i])))
				}

				// Uppercase time zone parts (remaining parts)
				timePart := make([]string, 0, len(parts)-3)
				for i := 3; i < len(parts); i++ {
					timePart = append(timePart, strings.ToUpper(parts[i]))
				}

				// Combine date and time parts
				formattedDate := strings.Join(datePart, " ") + " " + strings.Join(timePart, " ")

				// Parse the formatted date
				if parsedDate := email.ParseDate(formattedDate); parsedDate != nil {
					event.EventDate = parsedDate
				}
			}
		}

		// Extract IP address and event type
		if strings.HasPrefix(line, "ip address") {
			ip := common.ExtractOneIP(line)
			validIP := common.IsIP(ip)
			if validIP == "" {
				return nil, common.NewParserError("IP not found")
			}
			event.IP = validIP
			foundIP = true

			// Check if this is spam
			if strings.Contains(line, "spam") {
				event.EventTypes = []events.EventType{events.NewSpam()}
				foundEventType = true
			} else {
				subject, _ := common.GetSubject(serializedEmail, false)
				return nil, common.NewNewTypeError(subject)
			}
		}
	}

	// Ensure we found both IP and event type
	if !foundIP || !foundEventType {
		return nil, common.NewParserError("Required fields not found in email body")
	}

	return []*events.Event{event}, nil
}

// Parse parses emails from reports@dnainternet.net
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)

	// Check if subject contains expected keywords
	if strings.Contains(subjectLower, "[abuse report]") || strings.Contains(subjectLower, "abuse activity") {
		return parseSpamType(serializedEmail)
	}

	return nil, common.NewNewTypeError(subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
