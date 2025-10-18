package sbcglobal

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

var ipPattern = regexp.MustCompile(`\d{0,3}\.\d{0,3}\.\d{0,3}\.\d{0,3}`)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get from address
	fromAddr, err := common.GetFrom(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Get body and subject
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Get date fallback
	var dateFallback *time.Time
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			dateFallback = email.ParseDate(dateHeaders[0])
		}
	}

	// Route to appropriate parser based on from address
	if fromAddr == "glenn.white@sbcglobal.net" || fromAddr == "arniea@sbcglobal.net" {
		return parseWhite(body, dateFallback)
	} else if fromAddr == "sync@sbcglobal.net" {
		return parseSync(body, subject, dateFallback)
	}

	return nil, common.NewNewTypeError(subject)
}

func parseWhite(body string, dateFallback *time.Time) ([]*events.Event, error) {
	marker := "the websites and urls in this spam are for:"
	bodyLower := strings.ToLower(body)

	if strings.Contains(bodyLower, marker) {
		// Insert newline after marker to ensure it's on its own line
		bodyWithMarker := strings.Replace(bodyLower, marker, marker+"\n", 1)
		infoBlock := common.GetBlockAfterWithStop(bodyWithMarker, marker, "")

		var eventsList []*events.Event
		for _, line := range infoBlock {
			line = strings.ReplaceAll(line, "no match found for", "")
			// Check if line has content after removing dashes
			if strings.ReplaceAll(line, "-", "") != "" {
				event := events.NewEvent("sbcglobal")
				event.EventTypes = []events.EventType{events.NewSpam()}

				parts := strings.Fields(line)
				if len(parts) > 0 {
					event.URL = parts[0]
				}
				if len(parts) > 1 {
					// Try to set IP from second part
					potentialIP := parts[1]
					if validIP := common.IsIP(potentialIP); validIP != "" {
						event.IP = validIP
					}
				}

				// Only add event if we have IP or URL
				if event.IP != "" || event.URL != "" {
					event.EventDate = dateFallback
					eventsList = append(eventsList, event)
				}
			}
		}
		return eventsList, nil
	}

	// Alternative parsing: extract Received headers from body
	endIndex := strings.Index(bodyLower, "content-type: multipart/alternative")
	if endIndex != -1 {
		body = body[:endIndex]
	}

	// Split body into lines and mark Received headers
	bodyLines := strings.Split(body, "\n")
	var newBodyLines []string
	for _, line := range bodyLines {
		if strings.HasPrefix(line, "Received:") {
			newBodyLines = append(newBodyLines, "\nRECEIVED_MARKER\n"+line)
		} else {
			newBodyLines = append(newBodyLines, line)
		}
	}
	newBody := strings.Join(newBodyLines, "\n")

	// Extract all Received headers
	received := strings.Split(newBody, "\nRECEIVED_MARKER\n")
	var receivedHeaders []string
	for _, el := range received {
		if strings.Contains(el, "Received:") {
			receivedHeaders = append(receivedHeaders, el)
		}
	}

	if len(receivedHeaders) > 1 {
		// Discard the first Received address
		relevantRcvHeaders := receivedHeaders[1:]

		recInstance := email.NewReceivedHeader(relevantRcvHeaders)
		var eventsList []*events.Event

		for i, rcv := range relevantRcvHeaders {
			event := events.NewEvent("sbcglobal")
			event.EventTypes = []events.EventType{events.NewSpam()}

			// Try to extract IP from each line in the received header
			for _, line := range strings.Split(rcv, "\n") {
				if validIP := common.ExtractOneIP(line); validIP != "" {
					event.IP = validIP
					break
				}
			}

			if event.IP != "" {
				// Try to get date from received header
				if date := recInstance.ReceivedDate(i); date != nil {
					event.EventDate = date
				} else {
					event.EventDate = dateFallback
				}
				eventsList = append(eventsList, event)
			}
		}
		return eventsList, nil
	}

	return []*events.Event{}, nil
}

func parseSync(body, subject string, dateFallback *time.Time) ([]*events.Event, error) {
	marker := "web server access log"
	bodyLower := strings.ToLower(body)

	// Insert newline after marker to ensure it's on its own line
	bodyWithMarker := strings.Replace(bodyLower, marker, marker+"\n", 1)
	infoBlock := common.GetBlockAfterWithStop(bodyWithMarker, marker, "")

	// Extract all IPs from subject
	subjectIPs := ipPattern.FindAllString(subject, -1)

	var eventsList []*events.Event
	for _, ip := range subjectIPs {
		// Validate IP
		if validIP := common.IsIP(ip); validIP == "" {
			continue
		}

		event := events.NewEvent("sbcglobal")
		event.EventTypes = []events.EventType{events.NewWebHack()}
		event.IP = ip

		// Look for this IP in the info block to extract date
		for _, line := range infoBlock {
			if strings.HasPrefix(line, ip) {
				// Extract date between [ and ]
				dateStr := common.FindStringWithoutMarkers(line, "[", "]")
				if dateStr != "" {
					if parsedDate := email.ParseDate(dateStr); parsedDate != nil {
						event.EventDate = parsedDate
					} else {
						event.EventDate = dateFallback
					}
				} else {
					event.EventDate = dateFallback
				}
				eventsList = append(eventsList, event)
				break
			}
		}
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
