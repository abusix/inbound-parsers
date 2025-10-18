package ntt

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	emailAddressPattern = regexp.MustCompile(`(?i)(From: ).*(<\S+@\S+>)`)
)

func NewParser() *Parser {
	return &Parser{}
}

// getNewHeader processes header list and returns a new headers map
func getNewHeader(headerList []string, serializedEmail *email.SerializedEmail) map[string][]string {
	headerDic := make(map[string][]string)

	// Parse headers from list
	for _, line := range headerList {
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.ToLower(parts[0])
		value := parts[1]

		if key == "date" {
			// Try to parse date with the expected format
			format := "Mon, 02 Jan 2006 15:04:05 -0700"
			dateValue := strings.TrimSpace(value)
			parsedTime, err := time.Parse(format, dateValue)
			if err == nil {
				// Format as expected: "Mon Jan 02 2006 15:04:05"
				headerDic["date"] = []string{parsedTime.Format("Mon Jan 02 2006 15:04:05")}
			} else {
				// Fallback to original email date
				if originalDate, ok := serializedEmail.Headers["date"]; ok && len(originalDate) > 0 {
					headerDic["date"] = []string{originalDate[0]}
				}
			}
			continue
		}

		headerDic[key] = []string{value}
	}

	return headerDic
}

// rewrite processes emails with forwarded messages
func rewrite(serializedEmail *email.SerializedEmail) (*email.SerializedEmail, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	marker := "-------- Forwarded Message --------"

	// Check if there's exactly one email address in the body
	matches := emailAddressPattern.FindAllString(body, -1)
	if len(matches) != 1 {
		// If more than one match, it's a follow-up conversation
		return serializedEmail, nil
	}

	// Ensure marker is followed by newline
	body = strings.ReplaceAll(body, marker, marker+"\n")

	// Get header list after the marker
	headerList := common.GetBlockAfterWithStop(body, marker, "")

	// If we got a small number of headers, look for more after the last line
	if len(headerList) > 0 && len(headerList) < 3 {
		lastLine := headerList[len(headerList)-1]
		moreHeaders := common.GetBlockAfterWithStop(body, lastLine, "")
		headerList = append(headerList, moreHeaders...)
	}

	if len(headerList) == 0 {
		return serializedEmail, nil
	}

	// Split body after the last header line
	lastHeader := headerList[len(headerList)-1]
	bodyParts := strings.SplitN(body, lastHeader, 2)
	var newBody string
	if len(bodyParts) > 1 {
		newBody = bodyParts[1]
	}

	// Create new serialized email with updated headers and body
	newEmail := &email.SerializedEmail{
		Headers: getNewHeader(headerList, serializedEmail),
		Body:    newBody,
		Parts:   serializedEmail.Parts,
	}

	return newEmail, nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Check if this is a forwarded message that needs rewriting
	fromAddr, err := common.GetFrom(serializedEmail, false)
	if err == nil && strings.Contains(fromAddr, "@ntt.lt") {
		body, _ := common.GetBody(serializedEmail, false)
		if strings.Contains(strings.ToLower(body), "-------- forwarded message --------") {
			// Rewrite the email
			rewrittenEmail, err := rewrite(serializedEmail)
			if err != nil {
				return nil, err
			}
			serializedEmail = rewrittenEmail
		}
	}

	// After rewriting (or if no rewrite was needed), parse the email
	subject, _ := common.GetSubject(serializedEmail, false)
	return nil, common.NewNewTypeError(subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
