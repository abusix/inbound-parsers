package kinghost

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// XARFReport represents the XARF JSON structure
type XARFReport struct {
	Version      string       `json:"Version"`
	ReporterInfo ReporterInfo `json:"ReporterInfo"`
	Disclosure   bool         `json:"Disclosure"`
	Report       Report       `json:"Report"`
}

type ReporterInfo struct {
	ReporterOrg          string `json:"ReporterOrg"`
	ReporterOrgDomain    string `json:"ReporterOrgDomain"`
	ReporterOrgEmail     string `json:"ReporterOrgEmail"`
	ReporterContactName  string `json:"ReporterContactName"`
	ReporterContactEmail string `json:"ReporterContactEmail"`
	ReporterContactPhone string `json:"ReporterContactPhone"`
}

type Report struct {
	ReportClass   string   `json:"ReportClass"`
	ReportType    string   `json:"ReportType"`
	Date          string   `json:"Date"`
	SourceIP      string   `json:"SourceIp"`
	DestinationIP string   `json:"DestinationIp"`
	Ongoing       bool     `json:"Ongoing"`
	Samples       []Sample `json:"Samples"`
}

type Sample struct {
	ContentType   string `json:"ContentType"`
	Base64Encoded bool   `json:"Base64Encoded"`
	Description   string `json:"Description"`
	Payload       string `json:"Payload"`
}

// findTextXARFAttachment finds a JSON attachment containing XARF data
func findTextXARFAttachment(serializedEmail *email.SerializedEmail) (string, error) {
	// Try to find attachment with .json extension
	jsonAttachment, err := common.FindFirstAttachmentWithMimeType(serializedEmail, ".json")
	if err == nil {
		return jsonAttachment, nil
	}

	// Try to find attachment with "xarf" in filename
	for _, part := range serializedEmail.Parts {
		if part.Headers != nil {
			if disposition, ok := part.Headers["content-disposition"]; ok {
				for _, disp := range disposition {
					if strings.Contains(strings.ToLower(disp), "xarf") {
						switch body := part.Body.(type) {
						case string:
							return body, nil
						case []byte:
							return string(body), nil
						}
					}
				}
			}
		}
	}

	return "", fmt.Errorf("XARF attachment not found")
}

// convertXARF converts XARF data to an Event
func convertXARF(xarfData XARFReport) *events.Event {
	event := events.NewEvent("kinghost")

	// Set IP from SourceIP
	if xarfData.Report.SourceIP != "" {
		event.IP = xarfData.Report.SourceIP
	}

	// Set event date
	if xarfData.Report.Date != "" {
		event.EventDate = email.ParseDate(xarfData.Report.Date)
	}

	// Determine event type based on ReportType
	switch strings.ToLower(xarfData.Report.ReportType) {
	case "loginattack", "login_attack", "login-attack":
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	case "phishing", "fraud":
		event.EventTypes = []events.EventType{events.NewPhishing()}
	case "spam", "abuse":
		event.EventTypes = []events.EventType{events.NewSpam()}
	case "malware", "malwarehosting", "malware_hosting":
		event.EventTypes = []events.EventType{events.NewMalwareHosting()}
	case "bot", "botnet":
		event.EventTypes = []events.EventType{events.NewBot("")}
	case "ddos":
		event.EventTypes = []events.EventType{events.NewDDoS()}
	default:
		// Default to unknown type
		event.EventTypes = []events.EventType{events.NewUnknown()}
	}

	// Add reporter information as Organisation detail
	if xarfData.ReporterInfo.ReporterOrg != "" {
		event.AddEventDetail(&events.Organisation{
			Name:         xarfData.ReporterInfo.ReporterOrg,
			ContactName:  xarfData.ReporterInfo.ReporterContactName,
			ContactEmail: xarfData.ReporterInfo.ReporterContactEmail,
			ContactPhone: xarfData.ReporterInfo.ReporterContactPhone,
			URLOrDomain:  xarfData.ReporterInfo.ReporterOrgDomain,
		})
	}

	// Add samples as evidence or event details
	if len(xarfData.Report.Samples) > 0 {
		for _, sample := range xarfData.Report.Samples {
			event.AddEventDetail(&events.Sample{
				ContentType: sample.ContentType,
				Description: sample.Description,
				Payload:     sample.Payload,
			})
		}
	}

	// Add destination IP as target if present
	if xarfData.Report.DestinationIP != "" {
		event.AddEventDetail(&events.Target{
			IP: xarfData.Report.DestinationIP,
		})
	}

	return event
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, common.NewParserError("subject not found")
	}

	// Check for "Re:" in subject - reject replies
	if strings.Contains(subject, "Re:") {
		return nil, common.NewParserError("rejecting reply message")
	}

	// Find XARF attachment
	xarfAttachment, err := findTextXARFAttachment(serializedEmail)
	if err != nil {
		return nil, common.NewNewTypeError(subject)
	}

	// Parse XARF JSON
	var xarfData XARFReport
	if err := json.Unmarshal([]byte(xarfAttachment), &xarfData); err != nil {
		return nil, common.NewParserError("error while trying to convert to XARF")
	}

	// Convert XARF to event
	event := convertXARF(xarfData)

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
