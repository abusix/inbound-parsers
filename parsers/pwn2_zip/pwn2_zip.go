package pwn2_zip

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the pwn2_zip parser
type Parser struct{}

// Parse parses emails from soc@pwn2.zip containing XARF-format JSON attachments
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get date fallback from headers
	var dateFallback string
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			dateFallback = dateHeaders[0]
		}
	}

	// Find JSON attachment
	jsonAttachment, err := common.FindFirstAttachmentWithMimeType(serializedEmail, "json")
	if err != nil {
		return nil, common.NewParserError("JSON attachment not found: " + err.Error())
	}

	// Parse XARF format - split before "Samples" field and add closing braces
	// This handles the format where Samples is the last field and may be large
	samplesIdx := strings.Index(jsonAttachment, `"Samples"`)
	if samplesIdx == -1 {
		return nil, common.NewParserError("XARF format incomplete: 'Samples' field not found")
	}

	// Extract up to but not including "Samples" and close the JSON
	xarfJSON := jsonAttachment[:samplesIdx] + "}}"

	// Parse the JSON
	var xarfFormat map[string]interface{}
	if err := json.Unmarshal([]byte(xarfJSON), &xarfFormat); err != nil {
		return nil, common.NewParserError("failed to parse XARF JSON: " + err.Error())
	}

	// Extract Report section
	reportObj, ok := xarfFormat["Report"]
	if !ok {
		return nil, common.NewParserError("Report section not found in XARF format")
	}
	report, ok := reportObj.(map[string]interface{})
	if !ok {
		return nil, common.NewParserError("Report section has unexpected format")
	}

	// Check report type
	reportType := ""
	if rtObj, ok := report["ReportType"]; ok {
		if rt, ok := rtObj.(string); ok {
			reportType = strings.ToLower(rt)
		}
	}

	// Only handle malware type
	if reportType != "malware" {
		return nil, common.NewParserError(fmt.Sprintf("unsupported report type: %s", reportType))
	}

	// Create event
	event := events.NewEvent("pwn2_zip")
	event.EventTypes = []events.EventType{events.NewMalware("")}

	// Extract IP
	if ipObj, ok := report["SourceIp"]; ok {
		if ip, ok := ipObj.(string); ok {
			event.IP = ip
		}
	}

	// Extract port
	if portObj, ok := report["SourcePort"]; ok {
		switch p := portObj.(type) {
		case string:
			if portInt, err := common.ParsePort(p); err == nil {
				event.Port = portInt
			}
		case float64:
			event.Port = int(p)
		case int:
			event.Port = p
		}
	}

	// Extract reporter information
	reporterInfoObj, ok := xarfFormat["ReporterInfo"]
	if ok {
		if reporterInfo, ok := reporterInfoObj.(map[string]interface{}); ok {
			reporter := &events.Organisation{
				Name: "reporter",
			}

			if orgObj, ok := reporterInfo["ReporterOrg"]; ok {
				if org, ok := orgObj.(string); ok {
					reporter.Organisation = org
				}
			}

			if emailObj, ok := reporterInfo["ReporterOrgEmail"]; ok {
				if orgEmail, ok := emailObj.(string); ok {
					reporter.ContactEmail = orgEmail
				}
			}

			event.AddEventDetail(reporter)
		}
	}

	// Parse event date
	if dateObj, ok := report["Date"]; ok {
		if dateStr, ok := dateObj.(string); ok && dateStr != "" {
			eventDate := email.ParseDate(dateStr)
			if eventDate != nil {
				event.EventDate = eventDate
			} else if dateFallback != "" {
				// Fall back to email date header
				event.EventDate = email.ParseDate(dateFallback)
			}
		}
	} else if dateFallback != "" {
		// No date in report, use fallback
		event.EventDate = email.ParseDate(dateFallback)
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
