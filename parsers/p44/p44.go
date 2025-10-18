package p44

import (
	"encoding/json"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// extractXARFInformations extracts XARF JSON data from the email parts
func extractXARFInformations(serializedEmail *email.SerializedEmail) (*events.Event, error) {
	// Find the xarf.json attachment (second part, index 1)
	if len(serializedEmail.Parts) < 2 {
		return nil, common.NewParserError("xarf part could not be found")
	}

	xarfPart := serializedEmail.Parts[1]

	// Check content-disposition header contains xarf.json
	if xarfPart.Headers != nil {
		if disposition, ok := xarfPart.Headers["content-disposition"]; ok {
			found := false
			for _, disp := range disposition {
				if strings.Contains(strings.ToLower(disp), "xarf.json") {
					found = true
					break
				}
			}
			if !found {
				return nil, common.NewParserError("xarf part could not be found")
			}
		} else {
			return nil, common.NewParserError("xarf part could not be found")
		}
	} else {
		return nil, common.NewParserError("xarf part could not be found")
	}

	// Get body as string
	var xarfBody string
	switch body := xarfPart.Body.(type) {
	case string:
		xarfBody = body
	case []byte:
		xarfBody = string(body)
	default:
		return nil, common.NewParserError("unexpected part body type")
	}

	// Convert to lowercase for case-insensitive parsing
	xarfBodyLower := strings.ToLower(xarfBody)

	// Parse JSON
	var xarfData map[string]interface{}
	if err := json.Unmarshal([]byte(xarfBodyLower), &xarfData); err != nil {
		return nil, common.NewParserError("failed to parse XARF JSON: " + err.Error())
	}

	// Extract fields using find_string_without_markers equivalent
	// Since we have JSON, we can access fields directly
	date := getStringField(xarfData, "date")
	dstPort := getStringField(xarfData, "destinationport")
	ip := getStringField(xarfData, "sourceip")

	reporterOrg := getStringField(xarfData, "reporterorg")
	reporterOrgEmail := getStringField(xarfData, "reporterorgemail")
	reporterContactEmail := getStringField(xarfData, "reportercontactemail")
	reporterContactName := getStringField(xarfData, "reportercontactname")

	// Create reporter organisation
	reporter := &events.Organisation{
		Name:         "reporter",
		Organisation: reporterOrg,
		ContactEmail: reporterOrgEmail,
	}
	if reporterContactEmail != "" {
		reporter.ContactEmail = reporterContactEmail
	}
	if reporterContactName != "" {
		reporter.ContactName = reporterContactName
	}

	// Create event
	event := events.NewEvent("p44")

	// Set IP
	if ip != "" {
		if validIP := common.IsIP(ip); validIP != "" {
			event.IP = validIP
		}
	}

	// Set event date
	if date != "" {
		if parsedDate := email.ParseDate(date); parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	// Add target with port
	if dstPort != "" {
		target := &events.Target{
			Port: dstPort,
		}
		event.AddEventDetail(target)
	}

	// Add reporter
	event.AddEventDetail(reporter)

	return event, nil
}

// getStringField extracts a string field from a map[string]interface{}
func getStringField(data map[string]interface{}, key string) string {
	if val, ok := data[key]; ok {
		if strVal, ok := val.(string); ok {
			return strings.Trim(strVal, " ,\"")
		}
	}
	return ""
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)

	// Determine event type based on subject
	var eventType events.EventType
	if strings.Contains(subjectLower, "loginattack") {
		eventType = events.NewLoginAttack("", "")
	} else if strings.Contains(subjectLower, "portscan") {
		eventType = events.NewPortScan()
	} else {
		return nil, common.NewNewTypeError("adapt the parser")
	}

	// Extract XARF information
	event, err := extractXARFInformations(serializedEmail)
	if err != nil {
		return nil, err
	}

	// Set event type
	event.EventTypes = []events.EventType{eventType}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
