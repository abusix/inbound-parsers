package acns

import (
	"encoding/xml"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	xmlPattern          = regexp.MustCompile(`(?s)<\?xml[\s\S]*?<[iI]nfringement[\s\S]*?</[iI]nfringement>`)
	xmlEntityRefPattern = regexp.MustCompile(`&`)
)

// Infringement represents the ACNS XML structure
type Infringement struct {
	XMLName         xml.Name        `xml:"Infringement"`
	Case            Case            `xml:"Case"`
	Source          Source          `xml:"Source"`
	Content         Content         `xml:"Content"`
	Complainant     *Complainant    `xml:"Complainant"`
	ServiceProvider *ServiceProvider `xml:"Service_Provider"`
}

type Case struct {
	ID       string `xml:"ID"`
	Status   string `xml:"Status"`
	Severity string `xml:"Severity"`
}

type Source struct {
	IPAddress string `xml:"IP_Address"`
	TimeStamp string `xml:"TimeStamp"`
	Port      string `xml:"Port"`
	Type      string `xml:"Type"`
}

type Content struct {
	Item        []ContentItem `xml:"Item"`
	ContentItem []ContentItem `xml:"Content_Item"`
}

type ContentItem struct {
	Title     string `xml:"Title"`
	FileName  string `xml:"FileName"`
	FileSize  string `xml:"FileSize"`
	TimeStamp string `xml:"TimeStamp"`
	Hash      *Hash  `xml:"Hash"`
	URL       string `xml:"URL"`
}

type Hash struct {
	Text string `xml:",chardata"`
}

type Complainant struct {
	Entity string `xml:"Entity"`
	Email  string `xml:"Email"`
}

type ServiceProvider struct {
	Entity string `xml:"Entity"`
	Email  string `xml:"Email"`
}

func NewParser() *Parser {
	return &Parser{}
}

// isQuotedXMLPart checks if the XML is quoted (lines start with '>')
func isQuotedXMLPart(xmlPart string) bool {
	ratio := 0.9
	lines := 0
	quoteCount := 0
	quote := '>'

	for _, line := range strings.Split(xmlPart, "\n") {
		lines++
		if len(line) > 0 && rune(line[0]) == quote {
			quoteCount++
		}
	}

	if lines == 0 {
		return false
	}

	return float64(quoteCount)/float64(lines) >= ratio
}

// removeQuotes removes leading '>' from each line
func removeQuotes(xmlPart string) string {
	lines := strings.Split(xmlPart, "\n")
	if len(lines) == 0 {
		return xmlPart
	}

	var result strings.Builder
	result.WriteString(lines[0])
	result.WriteString("\n")

	for i := 1; i < len(lines); i++ {
		if len(lines[i]) > 0 {
			result.WriteString(lines[i][1:])
		}
		result.WriteString("\n")
	}

	return result.String()
}

// searchPartsForXML searches email parts for XML content
func searchPartsForXML(serializedEmail *email.SerializedEmail) string {
	for _, part := range serializedEmail.Parts {
		// Check if this is an XML content type
		if part.Headers != nil {
			if contentTypes, ok := part.Headers["content-type"]; ok {
				for _, ct := range contentTypes {
					if strings.Contains(strings.ToLower(ct), "application/xml") {
						// This is an XML part, extract the body
						var bodyStr string
						switch body := part.Body.(type) {
						case string:
							bodyStr = body
						case []byte:
							bodyStr = string(body)
						}

						if len(bodyStr) > 0 {
							if match := xmlPattern.FindString(bodyStr); match != "" {
								return match
							}
						}
					}
				}
			}
		}

		// Also search in non-XML parts
		var bodyStr string
		switch body := part.Body.(type) {
		case string:
			bodyStr = body
		case []byte:
			bodyStr = string(body)
		}

		if len(bodyStr) > 0 {
			if match := xmlPattern.FindString(bodyStr); match != "" {
				return match
			}
		}
	}

	return ""
}

// findXML finds and parses XML from the email
func findXML(serializedEmail *email.SerializedEmail) ([]*Infringement, error) {
	var xmlMatches []string

	// Try to find XML in body
	body, _ := common.GetBody(serializedEmail, false)
	if body != "" {
		matches := xmlPattern.FindAllString(body, -1)
		xmlMatches = append(xmlMatches, matches...)
	}

	// If not found in body, search parts
	if len(xmlMatches) == 0 {
		if match := searchPartsForXML(serializedEmail); match != "" {
			xmlMatches = append(xmlMatches, match)
		}
	}

	if len(xmlMatches) == 0 {
		return nil, common.NewParserError("no XML found in email")
	}

	// Parse each XML match
	var infringements []*Infringement
	for _, xmlMatch := range xmlMatches {
		content := strings.ReplaceAll(xmlMatch, "<br>", "")

		// Remove quotes if needed
		if isQuotedXMLPart(content) {
			content = removeQuotes(content)
		}

		// Fix XML entity references (& without proper entity)
		content = xmlEntityRefPattern.ReplaceAllString(content, "&amp;")

		// Parse XML
		var inf Infringement
		if err := xml.Unmarshal([]byte(content), &inf); err != nil {
			// Try case-insensitive parsing by normalizing tag case
			continue
		}

		infringements = append(infringements, &inf)
	}

	if len(infringements) == 0 {
		return nil, common.NewParserError("failed to parse XML content")
	}

	return infringements, nil
}

// createEvents creates events from parsed infringements
func createEvents(infringements []*Infringement) ([]*events.Event, error) {
	var allEvents []*events.Event

	for _, inf := range infringements {
		// Create base event template
		eventTemplate := events.NewEvent("acns")

		// Parse IP address
		needsURL := false
		ipStr := strings.TrimPrefix(inf.Source.IPAddress, "http://")
		ipStr = strings.TrimPrefix(ipStr, "https://")

		ip := net.ParseIP(ipStr)
		if ip != nil {
			eventTemplate.IP = ip.String()
		} else {
			needsURL = true
		}

		// Set event date
		if inf.Source.TimeStamp != "" {
			eventTemplate.EventDate = email.ParseDate(inf.Source.TimeStamp)
		}

		// Set port
		if inf.Source.Port != "" {
			if port, err := strconv.Atoi(inf.Source.Port); err == nil {
				eventTemplate.Port = port
			}
		}

		// Add torrent protocol
		if inf.Source.Type != "" {
			eventTemplate.AddEventDetail(&events.Torrent{
				Protocol: inf.Source.Type,
			})
		}

		// Add external case information
		caseInfo := &events.ExternalCaseInformation{
			CaseID:   inf.Case.ID,
			Status:   inf.Case.Status,
			Severity: inf.Case.Severity,
		}
		eventTemplate.AddEventDetail(caseInfo)

		// Add complainant information
		if inf.Complainant != nil {
			eventTemplate.AddEventDetail(&events.Organisation{
				Name:         "reporter",
				Organisation: inf.Complainant.Entity,
				ContactEmail: inf.Complainant.Email,
			})
		}

		// Add service provider information
		if inf.ServiceProvider != nil {
			email := inf.ServiceProvider.Email
			if email != "" {
				email = strings.ReplaceAll(email, "\n", "")
				email = strings.ReplaceAll(email, "\r", "")
			}
			eventTemplate.AddEventDetail(&events.OnBehalfOf{
				ComplainantEmail: email,
				ComplainantContact: inf.ServiceProvider.Entity,
			})
		}

		// Get content items
		var items []ContentItem
		if len(inf.Content.Item) > 0 {
			items = inf.Content.Item
		} else if len(inf.Content.ContentItem) > 0 {
			items = inf.Content.ContentItem
		} else {
			return nil, common.NewParserError("no content items found")
		}

		// Create an event for each item
		for _, item := range items {
			// Deep copy the event template
			event := events.NewEvent("acns")
			event.IP = eventTemplate.IP
			event.EventDate = eventTemplate.EventDate
			event.Port = eventTemplate.Port

			// Copy event details
			for _, detail := range eventTemplate.EventDetails {
				event.AddEventDetail(detail)
			}

			// Set event type
			event.EventTypes = []events.EventType{events.NewCopyright(item.Title, "", "")}

			// Add file information
			file := &events.File{
				FileName: item.FileName,
			}

			if item.FileSize != "" {
				file.FileSize = item.FileSize
			}

			if item.Hash != nil && item.Hash.Text != "" {
				file.FileHash = item.Hash.Text
			}

			event.AddEventDetail(file)

			// Add timestamp evidence
			if item.TimeStamp != "" {
				evidence := &events.Evidence{}
				evidence.AddEvidence(events.UrlStore{
					Description: "time_stamp",
					URL:         item.TimeStamp,
				})
				event.AddEventDetail(evidence)
			}

			// Set URL
			if item.URL != "" {
				event.URL = item.URL
			} else if needsURL {
				return nil, common.NewParserError("no IP or URL found")
			}

			allEvents = append(allEvents, event)
		}
	}

	return allEvents, nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Find and parse XML
	infringements, err := findXML(serializedEmail)
	if err != nil {
		return nil, err
	}

	// Create events from infringements
	return createEvents(infringements)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
