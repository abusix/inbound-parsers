// Package espresso implements the espresso parser
package espresso

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the espresso parser
type Parser struct{}

// extractDate extracts the date from the email body
func extractDate(body string, serializedEmail *email.SerializedEmail) (string, error) {
	lines := common.GetBlockAround(body, "Current records")
	if len(lines) == 0 {
		lines = common.GetBlockAround(body, "Fields:")
	}
	if len(lines) == 0 {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			return dateHeaders[0], nil
		}
		return "", nil
	}

	var timeZone string
	if strings.Contains(body, "GMT") {
		timeZone = "GMT"
	} else if strings.Contains(body, "CEST") {
		timeZone = "CEST"
	} else if strings.Contains(body, "CET") {
		timeZone = "CET"
	} else {
		return "", common.NewNewTypeError("new timezone detected")
	}

	for _, line := range lines {
		if strings.Contains(line, "\t") {
			fields := strings.Split(line, "\t")
			for _, field := range fields {
				if (strings.Contains(field, "/") || strings.Contains(field, "-")) &&
					strings.Contains(field, ":") && !strings.Contains(field, "http") {
					if strings.Contains(field, "+0") {
						timeZone = ""
					}
					if strings.Contains(field, "-") && strings.Contains(field, "T") {
						return strings.Replace(field, "T", " ", 1), nil
					} else if len(field) >= 8 {
						// Format: YYYYMMDD-HHMMSS or similar
						year := field[:4]
						month := field[4:6]
						rest := strings.ReplaceAll(strings.ReplaceAll(field[6:], "/", " "), "-", " ")
						return fmt.Sprintf("%s-%s-%s %s", year, month, rest, timeZone), nil
					}
				}
			}
		}
	}

	return "", common.NewParserError("no date detected, adapt the parser")
}

// parseSpam parses spam reports
func parseSpam(serializedEmail *email.SerializedEmail, subject string) ([]*events.Event, error) {
	regex := regexp.MustCompile(`\[\s*(\d{1,4}\.\d{1,4}\.\d{1,4}\.\d{1,4})\s*]\s*\[(.+?)]`)
	matches := regex.FindStringSubmatch(subject)
	if len(matches) >= 3 {
		event := events.NewEvent("espresso")
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
		event.EventTypes = []events.EventType{events.NewSpam()}
		event.IP = matches[1]
		event.URL = strings.Trim(matches[2], "\n\t,. ")
		return []*events.Event{event}, nil
	}
	return nil, common.NewParserError("spam pattern not matched")
}

// Parse parses emails from @abuse.espresso-gridpoint.net
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	if strings.Contains(subject, "spam") {
		return parseSpam(serializedEmail, subject)
	}

	var eventType events.EventType
	if strings.Contains(subject, "probe/scan/virus/trojan") {
		eventType = events.NewPortScan()
	} else if strings.Contains(subject, "RBL") {
		eventType = events.NewBlacklist("")
	} else {
		return nil, common.NewNewTypeError(subject)
	}

	date, err := extractDate(body, serializedEmail)
	if err != nil {
		return nil, err
	}

	srcIP := common.ExtractOneIP(subject)
	if srcIP == "" {
		return nil, common.NewParserError("no source IP found in subject")
	}
	srcIPParts := strings.Split(srcIP, ".")

	// Build regex pattern for matching log lines
	pattern := fmt.Sprintf(`%s\.%s\.%s\.%s\..*>.*:`, srcIPParts[0], srcIPParts[1], srcIPParts[2], srcIPParts[3])
	regex := regexp.MustCompile(pattern)

	matches := regex.FindAllString(body, -1)
	if len(matches) == 0 {
		event := events.NewEvent("espresso")
		event.EventDate = email.ParseDate(date)
		event.EventTypes = []events.EventType{eventType}
		event.IP = srcIP
		return []*events.Event{event}, nil
	}

	var result []*events.Event
	seen := make(map[string]bool)

	for _, logLine := range matches {
		parts := strings.Split(logLine, ">")
		if len(parts) < 2 {
			continue
		}

		src := strings.TrimSpace(parts[0])
		target := strings.TrimSpace(parts[1])

		if seen[src] {
			continue
		}
		seen[src] = true

		srcParts := strings.Split(src, ".")
		targetParts := strings.Split(target, ".")

		event := events.NewEvent("espresso")
		event.EventDate = email.ParseDate(date)
		event.EventTypes = []events.EventType{eventType}

		if len(srcParts) >= 5 {
			event.IP = strings.Join(srcParts[:4], ".")
			portStr := strings.TrimSuffix(srcParts[4], ":")
			if port, err := strconv.Atoi(portStr); err == nil {
				event.Port = port
			}
		}

		if len(targetParts) >= 4 {
			targetIP := strings.Join(targetParts[:4], ".")
			targetPort := ""
			if len(targetParts) >= 5 {
				portParts := strings.Split(targetParts[4], ":")
				if len(portParts) > 0 {
					targetPort = portParts[0]
				}
			}
			targetObj := &events.Target{IP: targetIP, Port: targetPort}
			event.AddEventDetail(targetObj)
		}

		result = append(result, event)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
