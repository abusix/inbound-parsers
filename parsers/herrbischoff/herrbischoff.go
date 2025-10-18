package herrbischoff

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

var datePattern = regexp.MustCompile(`(?i)(---\s*).*(?P<date>\[\d{1,2}/\S{1,5}/.*\])`)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)

	// Determine which parser to use
	if strings.Contains(subjectLower, "suspicious traffic") || strings.Contains(subjectLower, "abusive traffic") {
		return parseMalicious(subject, body, serializedEmail)
	} else if strings.Contains(strings.ToLower(body), "[ xarf report ]") {
		return parseXARF(body, serializedEmail)
	}

	return nil, fmt.Errorf("unknown email type: %s", subject)
}

func parseMalicious(subject, body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	event := events.NewEvent("herrbischoff")

	// Extract date from body using pattern
	if match := datePattern.FindStringSubmatch(body); match != nil {
		// Get the named group 'date'
		dateIdx := datePattern.SubexpIndex("date")
		if dateIdx >= 0 && dateIdx < len(match) {
			dateStr := match[dateIdx]
			// Remove brackets
			dateStr = strings.ReplaceAll(dateStr, "[", "")
			dateStr = strings.ReplaceAll(dateStr, "]", "")

			// Try to parse the date
			if parsedDate := email.ParseDate(dateStr); parsedDate != nil {
				event.EventDate = parsedDate
			}
		}
	}

	// If date extraction failed, use fallback date from headers
	if event.EventDate == nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
				event.EventDate = parsedDate
			}
		}
	}

	// Set event type
	event.EventTypes = []events.EventType{events.NewMaliciousActivity()}

	// Try to extract IP from subject
	ip := common.ExtractOneIP(subject)
	if ip != "" {
		event.IP = ip
	}

	// Only return event if IP is set
	if event.IP == "" {
		return nil, fmt.Errorf("no IP found in subject")
	}

	return []*events.Event{event}, nil
}

func parseXARF(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	event := events.NewEvent("herrbischoff")

	// Extract XARF report JSON
	xarfPattern := regexp.MustCompile(`(?i)(\[ XARF Report \]===============================)(?P<xarf_report>(\s*.*)*)`)
	match := xarfPattern.FindStringSubmatch(body)
	if match == nil {
		return nil, fmt.Errorf("XARF report not found in body")
	}

	xarfIdx := xarfPattern.SubexpIndex("xarf_report")
	if xarfIdx < 0 || xarfIdx >= len(match) {
		return nil, fmt.Errorf("XARF report group not found")
	}

	xarfReportStr := match[xarfIdx]

	// Parse JSON
	var xarfFormat map[string]interface{}
	if err := json.Unmarshal([]byte(xarfReportStr), &xarfFormat); err != nil {
		return nil, fmt.Errorf("failed to parse XARF JSON: %w", err)
	}

	// Get Report section
	report, ok := xarfFormat["Report"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("Report section not found in XARF format")
	}

	// Determine event type from ReportType
	reportType := ""
	if rt, ok := report["ReportType"].(string); ok {
		reportType = strings.ToLower(rt)
	}

	switch reportType {
	case "loginattack":
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	case "webappattack":
		event.EventTypes = []events.EventType{events.NewWebHack()}
	default:
		return nil, fmt.Errorf("new XARF report type found: %s", reportType)
	}

	// Extract SourceIP
	if sourceIP, ok := report["SourceIp"].(string); ok {
		event.IP = sourceIP
	}

	// Extract DestinationIP and add as Target
	if destIP, ok := report["DestinationIp"].(string); ok && destIP != "" {
		target := &events.Target{
			IP: destIP,
		}
		event.AddEventDetail(target)
	}

	// Extract reporter information
	if reporterInfo, ok := xarfFormat["ReporterInfo"].(map[string]interface{}); ok {
		reporterOrg := ""
		reporterEmail := ""

		if org, ok := reporterInfo["ReporterOrg"].(string); ok {
			reporterOrg = org
		}
		if email, ok := reporterInfo["ReporterOrgEmail"].(string); ok {
			reporterEmail = email
		}

		reporter := &events.Organisation{
			Name:         "reporter",
			Organisation: reporterOrg,
			ContactEmail: reporterEmail,
		}
		event.AddEventDetail(reporter)
	}

	// Extract event date
	if dateStr, ok := report["Date"].(string); ok {
		if parsedDate := email.ParseDate(dateStr); parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	// If date extraction failed, use fallback date from headers
	if event.EventDate == nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
				event.EventDate = parsedDate
			}
		}
	}

	// Extract samples
	if samplesRaw, ok := report["Samples"]; ok {
		if samples, ok := samplesRaw.([]interface{}); ok && len(samples) > 0 {
			if firstSample, ok := samples[0].(map[string]interface{}); ok {
				sample := &events.Sample{
					ContentType: getStringFromMap(firstSample, "ContentType"),
					Description: getStringFromMap(firstSample, "Description"),
					Payload:     getStringFromMap(firstSample, "Payload"),
				}
				event.AddEventDetail(sample)
			}
		}
	}

	return []*events.Event{event}, nil
}

// Helper function to safely extract string from map
func getStringFromMap(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
