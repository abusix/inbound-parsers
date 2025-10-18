package leakix

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
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
	body = strings.ReplaceAll(body, "\r", "")

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	if strings.Contains(subjectLower, "critical security issue") {
		event := events.NewEvent("leakix")

		// Extract plugin/service name
		plugin := common.FindStringWithoutMarkers(body, "Plugin", "")
		plugin = strings.ReplaceAll(plugin, " |", "")
		plugin = strings.TrimSpace(plugin)

		// Set Open event type with the service/plugin name
		event.EventTypes = []events.EventType{events.NewOpen(plugin)}

		// Extract URL from Source field
		url := common.FindStringWithoutMarkers(body, "Source", "")
		url = strings.ReplaceAll(url, " |", "")
		event.URL = strings.TrimSpace(url)

		// Extract IP (replace 'Ip' with 'IP' for consistent matching)
		bodyIP := strings.ReplaceAll(body, "Ip", "IP")
		ip := common.FindStringWithoutMarkers(bodyIP, "IP", "")
		event.IP = ip

		// Extract event date from Discovered field
		eventDate := common.FindStringWithoutMarkers(body, "Discovered", "")
		eventDate = strings.ReplaceAll(eventDate, " |", "")
		eventDate = strings.TrimSpace(eventDate)
		if eventDate != "" {
			// Parse and set event date
			event.EventDate = email.ParseDate(eventDate)
		}

		// Check for CVE information
		cvePattern := regexp.MustCompile(`Affected by CVE-(.*)`)
		if matches := cvePattern.FindAllStringSubmatch(body, -1); len(matches) > 0 {
			// Extract all CVE identifiers
			var cves []string
			for _, match := range matches {
				if len(match) > 1 {
					cves = append(cves, match[1])
				}
			}

			// Create CVE event type with the first CVE
			if len(cves) > 0 {
				cveType := events.NewCVE("CVE-"+cves[0], "", "")
				// Note: The Python version uses TListStore for cve_list field
				// In Go, we would need to add this field to the CVE struct if needed
				// For now, we create the CVE event type with the first CVE
				// Multiple CVEs would need to be handled by the CVE struct design
				event.EventTypes = []events.EventType{cveType}
			}
		}

		return []*events.Event{event}, nil
	}

	return nil, common.NewNewTypeError(subjectLower)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
