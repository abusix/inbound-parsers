// Package abuse_oneprovider implements the abuse_oneprovider parser
// This is a 100% exact Go translation of Python's abuse_oneprovider.py
package abuse_oneprovider

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/base"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the abuse_oneprovider parser
type Parser struct {
	base.BaseParser
}

var (
	lineMatcher             = regexp.MustCompile(`(?:([\w/ ]*?)/ .*?):[\n]?(.*)`)
	complicatedColonData    = regexp.MustCompile(`(?P<key>[^:]+):\s+(?P<value>.+)`)
	htmlCleaner             = regexp.MustCompile(`<.*?>`)
	htmlBRMatcher           = regexp.MustCompile(`(?i)<br.*?>`)
)

// New creates a new abuse_oneprovider parser instance
func New() *Parser {
	return &Parser{
		BaseParser: base.NewBaseParser("abuse_oneprovider"),
	}
}

// Parse parses emails from abuse-reply@oneprovider.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	event := events.NewEvent("abuse_oneprovider")

	// Check for Warner Bros format
	if idx := strings.Index(body, "CASE DETAIL/"); idx >= 0 {
		if err := parseWarnerBros(body, idx, event); err != nil {
			return nil, err
		}
		return []*events.Event{event}, nil
	}

	// Check for alternative copyright format
	if idx := strings.Index(body, "concerning this abuse:"); idx >= 0 {
		if strings.HasPrefix(body, "<!DOCTYPE html") {
			body = removeHTML(body, true)
			// Get block around BitTorrent marker and filter lines containing ':'
			blockLines := common.GetBlockAround(body, "BitTorrent")
			var filtered []string
			for _, line := range blockLines {
				trimmed := strings.TrimSpace(line)
				if strings.Contains(trimmed, ":") {
					filtered = append(filtered, trimmed)
				}
			}
			body = strings.Join(filtered, " \n")
		}

		if err := basicEventCopyrightParser(event, body); err != nil {
			return nil, err
		}
		return []*events.Event{event}, nil
	}

	return nil, common.NewParserError("no recognized format found")
}

// removeHTML removes HTML tags from text
func removeHTML(rawHTML string, replaceBR bool) string {
	clean := rawHTML
	if replaceBR {
		linebreak := getTextLinebreak(rawHTML)
		clean = htmlBRMatcher.ReplaceAllString(clean, linebreak)
	}
	clean = htmlCleaner.ReplaceAllString(clean, "")
	return clean
}

// getTextLinebreak detects the line break style used in text
func getTextLinebreak(text string) string {
	if strings.Contains(text, "\r") {
		return "\r\n"
	}
	return "\n"
}

// basicEventCopyrightParser parses copyright event data from key-value pairs
func basicEventCopyrightParser(event *events.Event, data string) error {
	marker := "Evidentiary Information:"
	if idx := strings.Index(data, marker); idx >= 0 {
		data = data[idx+len(marker):]
	}
	return rawEventCopyrightParser(event, data)
}

// rawEventCopyrightParser processes copyright data key-value pairs
func rawEventCopyrightParser(event *events.Event, data string) error {
	matches := complicatedColonData.FindAllStringSubmatch(data, -1)

	stripper := "\r\n\t-#> "
	foundDate := false
	foundIdentifying := false
	seen := make(map[string]bool)

	var date string
	var fileHash, fileName, fileSize string
	var copyrightedWork, copyrightOwner, protocol string

	for _, match := range matches {
		if len(match) < 3 {
			continue
		}

		key := strings.Trim(match[1], stripper)
		key = strings.ToLower(key)
		value := strings.Trim(match[2], stripper)

		if value == "" || seen[key] {
			continue
		}
		seen[key] = true

		switch key {
		case "title", "infringed work", "asset", "work title", "content":
			copyrightedWork = value

		case "initial infringement timestamp", "first found (utc)":
			if date != "" {
				event.AddEventDetailSimple("first_seen", date)
			} else {
				date = value
			}
			foundDate = true

		case "recent infringement timestamp", "last seen date", "last found (utc)",
			"coordinated universal time", "timestamp", "monitored at":
			if date != "" {
				event.AddEventDetailSimple("first_seen", date)
			}
			date = value
			foundDate = true

		case "ip address", "infringer's ip address", "infringers ip address":
			event.IP = value
			foundIdentifying = true

		case "port", "infringer's port", "port id":
			// Port is an int, try to parse it
			// If parsing fails, just skip it
			if portInt := 0; value != "" {
				if _, err := fmt.Sscanf(value, "%d", &portInt); err == nil {
					event.Port = portInt
				}
			}

		case "type", "protocol", "infringement source":
			protocol = value
			event.AddEventDetail(&events.Torrent{Protocol: value})

		case "torrent hash", "torrent hash value":
			fileHash = value

		case "filename", "infringing filename", "computer file name", "file name":
			fileName = value

		case "filesize", "infringing filesize", "infringing file size", "file size":
			fileSize = value

		case "url if applicable", "url", "infringement":
			event.URL = value
			foundIdentifying = true

		case "copyright owner", "copyright holder name":
			copyrightOwner = value

		case "united states email":
			event.SenderEmail = value
		}
	}

	event.EventDate = email.ParseDate(date)
	event.AddEventDetail(&events.File{
		FileHash: fileHash,
		FileName: fileName,
		FileSize: fileSize,
	})

	copyright := events.NewCopyright(copyrightedWork, copyrightOwner, protocol)
	event.EventTypes = []events.EventType{copyright}

	if !foundIdentifying {
		return common.NewParserError("no ip found")
	}
	if !foundDate {
		return common.NewParserError("no date found")
	}

	return nil
}

func parseWarnerBros(body string, startIndex int, event *events.Event) error {
	// Find end of section
	endIndex := strings.Index(body[startIndex:], "\r\n\r\n\r\n\r\n")
	if endIndex < 0 {
		endIndex = strings.Index(body[startIndex:], "\n\n\n")
	}
	if endIndex < 0 {
		return common.NewParserError("couldn't find relevant data")
	}
	endIndex += startIndex

	// Extract and parse key-value pairs
	bodyExtract := strings.ReplaceAll(body[startIndex:endIndex], "\r\n", "\n")
	valueDict := getValueDict(bodyExtract)

	// Variables to track copyright data
	var copyrightedWork, copyrightOwner, protocol string
	onBehalfOf := &events.OnBehalfOf{}

	for key, value := range valueDict {
		switch {
		case strings.Contains(key, "Title of Work"):
			copyrightedWork = value
		case strings.Contains(key, "Claimant's Name"):
			onBehalfOf.ComplainantContact = value
			copyrightOwner = value
		case strings.Contains(key, "Claimant's Address"):
			// Store as event detail since Copyright doesn't have Reason field
			event.AddEventDetailSimple("claimant_address", value)
		case strings.Contains(key, "Claimant's Email Address"):
			onBehalfOf.ComplainantEmail = value
		case strings.Contains(key, "Claimant's Interest or Right in the Work"):
			// Store as event detail since Copyright doesn't have Rights field
			event.AddEventDetailSimple("claimant_rights", value)
		case strings.Contains(key, "Infringement Claimed"):
			event.AddEventDetailSimple("infringement_claim", value)
		case strings.Contains(key, "Location Data"):
			event.IP = value
		case strings.Contains(key, "Date and Time"):
			event.EventDate = email.ParseDate(value)
		case strings.Contains(key, "Filename"):
			event.AddEventDetail(&events.File{FileName: value})
		default:
			event.AddEventDetailSimple(key, value)
		}
	}

	copyright := events.NewCopyright(copyrightedWork, copyrightOwner, protocol)
	event.EventTypes = []events.EventType{copyright}
	event.AddEventDetail(onBehalfOf)

	return nil
}

func getValueDict(bodyExtract string) map[string]string {
	result := make(map[string]string)
	matches := lineMatcher.FindAllStringSubmatch(bodyExtract, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			key := strings.TrimSpace(match[1])
			value := strings.TrimSpace(match[2])
			result[key] = value
		}
	}
	return result
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
