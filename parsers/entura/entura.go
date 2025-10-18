// Package entura implements the entura parser
package entura

import (
	"strconv"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the entura parser
type Parser struct{}

// findAndCleanLines finds content between markers and splits into clean lines
func findAndCleanLines(base, startsWith, endsWith string) map[string]bool {
	result := make(map[string]bool)
	content := common.FindStringWithoutMarkers(base, startsWith, endsWith)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			result[trimmed] = true
		}
	}
	return result
}

// findFittingIP finds IPs that appear in the given URL
func findFittingIP(url string, ipCandidates map[string]bool) []string {
	var result []string
	for candidate := range ipCandidates {
		ip := common.ExtractOneIP(candidate)
		if ip != "" {
			validIP := common.IsIP(ip)
			if validIP != "" && strings.Contains(url, validIP) {
				result = append(result, validIP)
			}
		}
	}
	return result
}

// parseBitTorrentInfringement parses BitTorrent infringement reports
func parseBitTorrentInfringement(body string, serializedEmail *email.SerializedEmail) (*events.Event, error) {
	event := events.NewEvent("entura")

	bodyLower := strings.ToLower(body)

	if strings.Contains(bodyLower, "details relating to the observed infringement:") {
		copyright := events.NewCopyright("", "", "")
		copyright.CopyrightOwner = common.FindStringWithoutMarkers(body, "on behalf of", ".")
		copyright.CopyrightedWork = common.FindStringWithoutMarkers(body, "Title:", "")

		dateStr := common.FindStringWithoutMarkers(body, "Timestamp:", "")
		event.EventDate = email.ParseDate(dateStr)

		event.IP = common.FindStringWithoutMarkers(body, "IP Address:", "")

		portStr := common.FindStringWithoutMarkers(body, "Port:", "")
		if port, err := strconv.Atoi(portStr); err == nil {
			event.Port = port
		}

		copyright.Protocol = common.FindStringWithoutMarkers(body, "Type:", "")

		file := &events.File{
			FileHash: common.FindStringWithoutMarkers(body, "Torrent Hash:", ""),
			FileName: common.FindStringWithoutMarkers(body, "Filename:", ""),
		}
		event.AddEventDetail(file)
		event.EventTypes = []events.EventType{copyright}
		return event, nil
	} else if strings.Contains(bodyLower, "summarized for you at the bottom") {
		copyright := events.NewCopyright("", "", "")
		reporter := &events.Organisation{
			ContactName:  common.GetNonEmptyLineAfter(body, "Claimant's Name"),
			Address:      common.GetNonEmptyLineAfter(body, "Claimant's Address"),
			ContactEmail: common.GetNonEmptyLineAfter(body, "Claimant's Email"),
		}
		copyright.CopyrightedWork = common.GetNonEmptyLineAfter(body, "Title of Work")
		event.IP = common.GetNonEmptyLineAfter(body, "Electronic Location")
		dateStr := common.GetNonEmptyLineAfter(body, "Date and Time")
		event.EventDate = email.ParseDate(dateStr)
		event.AddEventDetail(reporter)

		file := &events.File{
			FileName: common.GetNonEmptyLineAfter(body, "Filename"),
		}
		event.AddEventDetail(file)
		event.EventTypes = []events.EventType{copyright}
		return event, nil
	}

	return nil, common.NewParserError("unknown bittorrent infringement format")
}

// Parse parses emails from @entura.co.uk and @entura-international.co.uk
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Check for BitTorrent infringement
	if strings.Contains(strings.ToLower(subject), "bittorrent content infringement") {
		event, err := parseBitTorrentInfringement(body, serializedEmail)
		if err != nil {
			return nil, err
		}
		return []*events.Event{event}, nil
	}

	// Parse regular copyright reports
	var date *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		date = email.ParseDate(dateHeaders[0])
	}

	urls := findAndCleanLines(body, "Infringing URLs/Identifiers:", "Copyright Infringer Details:")
	ipLines := findAndCleanLines(body, "Copyright Infringer Details:", " - ")

	ips := make(map[string]bool)
	for line := range ipLines {
		ip := common.ExtractOneIP(line)
		if ip != "" {
			validIP := common.IsIP(ip)
			if validIP != "" {
				ips[validIP] = true
			}
		}
	}

	var singleIP string
	if len(ips) == 1 {
		for ip := range ips {
			singleIP = ip
			break
		}
	}

	work := strings.TrimSpace(common.GetNonEmptyLineAfter(body, "Copyright Protected Work"))
	if strings.Contains(work, "'") {
		work = strings.TrimSpace(common.FindStringWithoutMarkers(work, "'", "'"))
	}

	evidence := &events.Evidence{}
	evidenceBlock := common.GetBlockAfterWithStop(body, "Evidence of Entura", "")
	if len(evidenceBlock) > 0 {
		urlStore := events.UrlStore{Description: "", URL: evidenceBlock[0]}
		evidence.AddEvidence(urlStore)
	}

	externalID := common.FindStringWithoutMarkers(subject+"<end>", "#", "<end>")
	if externalID == "" {
		externalID = common.FindStringWithoutMarkers(subject+"<end>", "ID: ", "<end>")
	}

	rightsHolder := strings.TrimSpace(common.FindStringWithoutMarkers(body, "behalf of ", "("))

	var result []*events.Event

	if len(urls) == 1 {
		var url string
		for u := range urls {
			url = u
			break
		}
		for ip := range ips {
			event := events.NewEvent("entura")
			event.URL = url
			event.EventDate = date
			event.IP = ip
			copyright := events.NewCopyright(work, rightsHolder, "")
			event.EventTypes = []events.EventType{copyright}
			if externalID != "" {
				event.AddEventDetail(&events.ExternalID{ID: externalID})
			}
			event.AddEventDetail(evidence)
			result = append(result, event)
		}
	} else {
		for url := range urls {
			event := events.NewEvent("entura")
			event.URL = url
			event.EventDate = date

			if singleIP != "" {
				event.IP = singleIP
			} else {
				ipCandidates := findFittingIP(url, ips)
				if len(ipCandidates) > 0 {
					event.IP = ipCandidates[0]
				}
				// If no IP found, continue anyway as URL might be enough
			}

			copyright := events.NewCopyright(work, rightsHolder, "")
			event.EventTypes = []events.EventType{copyright}
			if externalID != "" {
				event.AddEventDetail(&events.ExternalID{ID: externalID})
			}
			event.AddEventDetail(evidence)
			result = append(result, event)
		}
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
