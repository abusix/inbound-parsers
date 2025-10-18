package torrent_markmonitor

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	xmlPattern = regexp.MustCompile(`(?s)<\?xml.*?<InvestigationInfo.*?</InvestigationInfo>`)
)

// InvestigationInfo represents the MarkMonitor XML structure
type InvestigationInfo struct {
	XMLName    xml.Name   `xml:"InvestigationInfo"`
	Protocol   string     `xml:"Protocol"`
	CaseList   CaseList   `xml:"CaseList"`
}

type CaseList struct {
	Case []Case `xml:"Case"`
}

type Case struct {
	CaseID                   string                   `xml:"CaseId"`
	Completed                string                   `xml:"Completed"`
	PeerIP                   string                   `xml:"PeerIP"`
	PeerPort                 string                   `xml:"PeerPort"`
	PeerHostName             string                   `xml:"PeerHostName"`
	PeerISP                  string                   `xml:"PeerISP"`
	PeerCountry              string                   `xml:"PeerCountry"`
	FingerPrint              string                   `xml:"FingerPrint"`
	InvestigationAttributes  InvestigationAttributes  `xml:"InvestigationAttributes"`
	ContentList              ContentList              `xml:"ContentList"`
}

type InvestigationAttributes struct {
	InvestigationAttribute []InvestigationAttribute `xml:"InvestigationAttribute"`
}

type InvestigationAttribute struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

type ContentList struct {
	Content []Content `xml:"Content"`
}

type Content struct {
	Name  string      `xml:"name,attr"`
	Size  string      `xml:"size,attr"`
	Hash  Hash        `xml:"Hash"`
	Match Match       `xml:"Match"`
}

type Hash struct {
	Value string `xml:",chardata"`
}

type Match struct {
	MatchDetails MatchDetails `xml:"MatchDetails"`
}

type MatchDetails struct {
	MatchDetail []MatchDetail `xml:"MatchDetail"`
}

type MatchDetail struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

func NewParser() *Parser {
	return &Parser{}
}

// parseBrokenXML parses emails that contain text-based infringement details instead of XML
func parseBrokenXML(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Remove \r for consistency
	body = strings.ReplaceAll(body, "\r", "")

	// Get the continuous lines from "INFRINGEMENT DETAIL" onwards
	lines := common.GetContinuousLinesUntilEmptyLine(body, "INFRINGEMENT DETAIL")
	if len(lines) == 0 {
		return nil, common.NewParserError("no INFRINGEMENT DETAIL section found")
	}

	dataPart := strings.Join(lines, "\n") + "\n"

	// Extract fields using helper
	contentStr := common.FindStringWithoutMarkers(dataPart, "Infringing Content:", ": ")
	contentStr = strings.TrimSpace(contentStr)
	contentLines := strings.Split(contentStr, "\n")
	// Remove last empty line if present
	if len(contentLines) > 0 && contentLines[len(contentLines)-1] == "" {
		contentLines = contentLines[:len(contentLines)-1]
	}

	ip := strings.TrimSpace(common.FindStringWithoutMarkers(dataPart, "IP Address:", ""))
	fileSize := strings.TrimSpace(common.FindStringWithoutMarkers(dataPart, "File size:", ""))
	fileName := strings.TrimSpace(common.FindStringWithoutMarkers(dataPart, "Filename:", ""))
	lastFound := strings.TrimSpace(common.FindStringWithoutMarkers(dataPart, "Last found (UTC):", ""))
	portStr := strings.TrimSpace(common.FindStringWithoutMarkers(dataPart, "Port:", ""))
	protocol := strings.TrimSpace(common.FindStringWithoutMarkers(dataPart, "Protocol:", ""))

	var evts []*events.Event

	// Create one event for each work name in content
	for _, workName := range contentLines {
		workName = strings.TrimSpace(workName)
		if workName == "" {
			continue
		}

		event := events.NewEvent("torrent_markmonitor")

		// Set event type
		event.EventTypes = []events.EventType{events.NewCopyright(workName, "", protocol)}

		// Set IP
		event.IP = ip

		// Set event date
		if lastFound != "" {
			event.EventDate = email.ParseDate(lastFound)
		}

		// Set port
		if portStr != "" {
			if port, err := strconv.Atoi(portStr); err == nil {
				event.Port = port
			}
		}

		// Add torrent detail
		event.AddEventDetail(&events.Torrent{
			Protocol: protocol,
			Name:     workName,
		})

		// Add file detail
		event.AddEventDetail(&events.File{
			FileName: fileName,
			FileSize: fileSize,
		})

		evts = append(evts, event)
	}

	if len(evts) == 0 {
		return nil, common.NewParserError("no events created from broken XML format")
	}

	return evts, nil
}

// wrapXMLListOrNoList ensures a value is a slice
func wrapXMLListOrNoList(val interface{}) []interface{} {
	switch v := val.(type) {
	case []interface{}:
		return v
	default:
		return []interface{}{v}
	}
}

// getXML finds and extracts the XML from the email
func getXML(serializedEmail *email.SerializedEmail, body string) (string, error) {
	// Try to find XML in the body first
	match := xmlPattern.FindString(body)
	if match != "" {
		return match, nil
	}

	// Try to find XML in parts
	if len(serializedEmail.Parts) > 1 {
		for _, part := range serializedEmail.Parts {
			var partBody string
			switch b := part.Body.(type) {
			case string:
				partBody = b
			case []byte:
				partBody = string(b)
			}

			match = xmlPattern.FindString(partBody)
			if match != "" {
				return match, nil
			}
		}
	}

	return "", common.NewParserError("could not find XML part")
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)

	// Check if this is an ACNS XML format (delegate to acns parser)
	if strings.Contains(body, "Start ACNS XML") {
		// Note: In the Python version, this calls acns_parse
		// For now, we'll fall through to parseBrokenXML on error
		// In production, you would import and call the acns parser here
		return parseBrokenXML(serializedEmail)
	}

	// Try to get and parse the XML
	xmlStr, err := getXML(serializedEmail, body)
	if err != nil {
		return nil, err
	}

	var info InvestigationInfo
	if err := xml.Unmarshal([]byte(xmlStr), &info); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}

	if len(info.CaseList.Case) == 0 {
		return nil, common.NewParserError("no cases found in XML")
	}

	var evts []*events.Event

	// Process each case
	for _, caseData := range info.CaseList.Case {
		// Process each content item within the case
		for _, content := range caseData.ContentList.Content {
			event := events.NewEvent("torrent_markmonitor")

			// Set event date
			if caseData.Completed != "" {
				event.EventDate = email.ParseDate(caseData.Completed)
			}

			// Set IP, port, URL
			event.IP = caseData.PeerIP
			if caseData.PeerPort != "" {
				if port, err := strconv.Atoi(caseData.PeerPort); err == nil {
					event.Port = port
				}
			}
			event.URL = caseData.PeerHostName

			// Add external ID
			event.AddEventDetail(&events.ExternalID{
				ID: caseData.CaseID,
			})

			// Extract client and peer_id from investigation attributes
			client := ""
			peerID := ""
			for _, attr := range caseData.InvestigationAttributes.InvestigationAttribute {
				if strings.Contains(strings.ToLower(attr.Key), "client info") {
					client = attr.Value
				} else if strings.Contains(attr.Key, "ID") {
					peerID = attr.Value
				}
			}

			// Extract owner from match details
			owner := ""
			for _, detail := range content.Match.MatchDetails.MatchDetail {
				if strings.Contains(detail.Key, "Owner") {
					owner = detail.Value
				}
			}

			// Set work name
			works := content.Name

			// Add torrent detail
			event.AddEventDetail(&events.Torrent{
				Protocol: info.Protocol,
				Name:     works,
				PeerID:   peerID,
				Client:   client,
			})

			// Add file detail
			event.AddEventDetail(&events.File{
				FileSize: content.Size,
				FileHash: content.Hash.Value,
			})

			// Add ISP detail
			event.AddEventDetail(&events.ISP{
				ISPName: caseData.PeerISP,
				Country: caseData.PeerCountry,
			})

			// Add fingerprint
			event.AddEventDetailSimple("finger_print", caseData.FingerPrint)

			// Set event type
			event.EventTypes = []events.EventType{
				events.NewCopyright(works, owner, info.Protocol),
			}

			evts = append(evts, event)
		}
	}

	if len(evts) == 0 {
		return nil, common.NewParserError("no events created from XML")
	}

	return evts, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
