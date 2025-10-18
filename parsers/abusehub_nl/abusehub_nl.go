package abusehub_nl

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/base"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct {
	base.BaseParser
}

func New() *Parser {
	return &Parser{
		BaseParser: base.NewBaseParser("abusehub_nl"),
	}
}

// getAttachment extracts the first attachment and determines its type
func getAttachment(serializedEmail *email.SerializedEmail) (string, string, error) {
	for _, part := range serializedEmail.Parts {
		if part.Headers == nil {
			continue
		}

		// Check content-disposition for attachment filename
		if disposition, ok := part.Headers["content-disposition"]; ok && len(disposition) > 0 {
			dispStr := disposition[0]
			// Extract extension from filename by looking at the last part after '.'
			parts := strings.Split(dispStr, ".")
			if len(parts) > 1 {
				ext := strings.Trim(parts[len(parts)-1], " \"'")
				if ext == "xml" {
					body, err := getPartBody(part)
					if err == nil && body != "" {
						return "xml", body, nil
					}
				} else if ext == "csv" {
					body, err := getPartBody(part)
					if err == nil && body != "" {
						return "csv", body, nil
					}
				}
			}
		}
	}

	return "", "", common.NewParserError("no attachment found")
}

// getPartBody extracts body from an email part
func getPartBody(part email.EmailPart) (string, error) {
	switch body := part.Body.(type) {
	case string:
		return body, nil
	case []byte:
		return string(body), nil
	default:
		return "", fmt.Errorf("unexpected part body type: %T", body)
	}
}

// parseCSV parses CSV attachment
func parseCSV(attachment string) ([]*events.Event, error) {
	reader := csv.NewReader(strings.NewReader(attachment))
	reader.TrimLeadingSpace = true

	// Read header
	headers, err := reader.Read()
	if err != nil {
		return nil, common.NewParserError("failed to read CSV headers: " + err.Error())
	}

	var result []*events.Event

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, common.NewParserError("failed to read CSV row: " + err.Error())
		}

		event := events.NewEvent("abusehub_nl")

		// Build a map from headers to values
		row := make(map[string]string)
		for i, value := range record {
			if i < len(headers) {
				row[headers[i]] = value
			}
		}

		// Parse event date and time
		if eventDate, ok := row["event_date"]; ok {
			if eventTime, ok := row["event_time"]; ok {
				// Combine date and time with +02:00 timezone as in Python
				dateTimeStr := fmt.Sprintf("%s %s +02:00", eventDate, eventTime)
				// Parse the datetime: format like "2024-10-18 12:00:00 +02:00"
				parsedTime, err := time.Parse("2006-01-02 15:04:05 -07:00", dateTimeStr)
				if err == nil {
					event.EventDate = &parsedTime
				}
				delete(row, "event_date")
				delete(row, "event_time")
			}
		}

		// Parse report type to determine event type
		reportType := ""
		if rt, ok := row["report_type"]; ok {
			reportType = strings.ToLower(strings.ReplaceAll(rt, "_", " "))
			delete(row, "report_type")
		}

		// Set event type based on report_type
		if reportType != "" {
			if strings.Contains(reportType, "fbl") {
				event.EventTypes = []events.EventType{events.NewSpam()}
			} else if strings.Contains(reportType, "spamhaus bot") {
				event.EventTypes = []events.EventType{events.NewBot("")}
			} else if strings.Contains(reportType, "shadowserver") {
				// TODO: Call shadowserver.get_type(report_type) when available
				event.EventTypes = []events.EventType{events.NewBot("")}
				event.AddEventDetailSimple("shadowserver_type", reportType)
			} else if strings.Contains(reportType, "n6") {
				event.EventTypes = []events.EventType{events.NewMalware(reportType)}
			} else if strings.Contains(reportType, "vpn") {
				// Map service strings - simplified version without full mapping
				service := reportType
				event.EventTypes = []events.EventType{events.NewOpen(service)}
			} else {
				// Unknown type - continue but add as detail
				event.AddEventDetailSimple("unknown_report_type", reportType)
				event.EventTypes = []events.EventType{events.NewBot("")}
			}
		}

		// Extract source IP
		if srcIP, ok := row["src_ip"]; ok {
			ip := common.IsIP(srcIP)
			if ip != "" {
				event.IP = ip
			}
			delete(row, "src_ip")
		}

		// Add remaining fields as event details
		for key, value := range row {
			value = strings.TrimSpace(value)
			if value != "" {
				event.AddEventDetailSimple(key, value)
			}
		}

		// Only add event if it has an IP
		if event.IP != "" {
			result = append(result, event)
		}
	}

	if len(result) == 0 {
		return nil, common.NewParserError("no events created from CSV")
	}

	return result, nil
}

// parseXML parses XML IODEF attachment
func parseXML(attachment string, identifier string) ([]*events.Event, error) {
	// TODO: Implement IODEF XML parsing
	// The Python version uses the iodef library to parse XML in IODEF format
	// This requires:
	// 1. XML parsing with IODEF schema support
	// 2. Extracting incident data, IP addresses, ASN, port, protocol
	// 3. Determining event type based on original_report_type and original_notifier
	//
	// Event type mapping from Python:
	// - "shadowserver" in report_type -> shadowserver.get_type()
	// - "spamhaus bot" -> Bot(bot_type=method)
	// - "hotmail fbl" -> Spam()
	// - "cert polska" -> Blacklist() or Bot() based on report
	// - "xs4all" -> Spam()
	// - "vpn" -> Open(service)
	//
	// Since Go doesn't have a built-in IODEF parser library like Python,
	// this would require custom XML parsing or a third-party library.
	// For now, returning an error to indicate XML is not yet supported.

	return nil, common.NewParserError("XML/IODEF parsing not yet implemented in Go version")
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	attachmentType, attachment, err := getAttachment(serializedEmail)
	if err != nil {
		return nil, err
	}

	if attachmentType == "xml" {
		return parseXML(attachment, serializedEmail.Identifier)
	} else if attachmentType == "csv" {
		return parseCSV(attachment)
	}

	return nil, common.NewParserError(fmt.Sprintf("unknown attachment type: %s", attachmentType))
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
