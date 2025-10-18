package bka

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
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
	bodyLower := strings.ToLower(body)

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	// Get sender email from metadata
	fromAddr := ""
	if serializedEmail.Metadata.EnvelopeFrom != "" {
		fromAddr = serializedEmail.Metadata.EnvelopeFrom
	}

	// Get event date from headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	var resultEvents []*events.Event

	// Handle abuse-report@bka.bund.de
	if fromAddr == "abuse-report@bka.bund.de" {
		rawCSV, err := common.FindFirstAttachmentWithMimeType(serializedEmail, ".csv")
		if err != nil {
			return nil, err
		}

		csvData, err := common.ParseCSVString(rawCSV)
		if err != nil {
			return nil, err
		}

		// Determine event type based on body content
		var eventType events.EventType
		if strings.Contains(bodyLower, "betrug") {
			eventType = events.NewFraud()
		} else if strings.Contains(bodyLower, "urheberrechtlich geschützt") {
			eventType = events.NewCopyright("", "", "")
		} else {
			// Default to fraud if no clear match
			eventType = events.NewFraud()
		}

		// Parse each CSV entry
		for _, entry := range csvData {
			event := events.NewEvent("bka")
			event.EventTypes = []events.EventType{eventType}
			event.EventDate = eventDate
			event.IP = entry["IP"]
			event.URL = entry["URL"]
			resultEvents = append(resultEvents, event)
		}
	} else if fromAddr == "abuse@cyber.bka.de" {
		// Handle abuse@cyber.bka.de - malware reports
		if strings.Contains(subjectLower, "malware") && len(serializedEmail.Parts) > 1 {
			// Check if parts[1] has .txt in content-disposition
			if serializedEmail.Parts[1].Headers != nil {
				if disposition, ok := serializedEmail.Parts[1].Headers["content-disposition"]; ok {
					hasTxt := false
					for _, disp := range disposition {
						if strings.Contains(strings.ToLower(disp), ".txt") {
							hasTxt = true
							break
						}
					}

					if hasTxt {
						// Get CSV from parts[1].body
						var csvPart string
						switch body := serializedEmail.Parts[1].Body.(type) {
						case string:
							csvPart = body
						case []byte:
							csvPart = string(body)
						default:
							return nil, fmt.Errorf("unexpected parts[1] body type: %T", body)
						}

						// Extract malware name from body
						malware := ""
						re := regexp.MustCompile(`by the malicious\s*(<br>)?\s*software (\S+)`)
						if matches := re.FindStringSubmatch(bodyLower); len(matches) > 2 {
							malware = strings.ReplaceAll(matches[2], "\"", "")
						}

						// Parse CSV
						csvData, err := common.ParseCSVString(csvPart)
						if err != nil {
							return nil, err
						}

						// Create events for each CSV entry
						for _, entry := range csvData {
							event := events.NewEvent("bka")
							event.EventTypes = []events.EventType{events.NewMalware(malware)}

							// Parse timestamp from CSV
							if timestamp := entry["timestamp"]; timestamp != "" {
								if parsedDate := email.ParseDate(timestamp); parsedDate != nil {
									event.EventDate = parsedDate
								}
							}

							event.IP = entry["ip_address"]
							resultEvents = append(resultEvents, event)
						}
					}
				}
			}
		}
	}

	return resultEvents, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
