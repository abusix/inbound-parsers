// Package ecucert implements the ecucert parser for Ecuador CERT reports
package ecucert

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the ecucert parser
type Parser struct{}

// Parse parses CSV/ZIP attachments from Ecuador CERT
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Check if closed
	if strings.Contains(body, "bajo el estado CERRADO") {
		return []*events.Event{}, nil
	}

	// Get last attachment
	if len(serializedEmail.Parts) == 0 {
		return nil, common.NewParserError("no attachment found")
	}

	attachment := serializedEmail.Parts[len(serializedEmail.Parts)-1]

	// Get CSV data
	csvLines, err := getValidCSV(attachment)
	if err != nil {
		return nil, err
	}

	// Parse CSV
	reader := csv.NewReader(strings.NewReader(strings.Join(csvLines, "\n")))
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return nil, common.NewParserError("failed to parse CSV: " + err.Error())
	}

	if len(records) < 2 {
		return nil, common.NewParserError("CSV has no data rows")
	}

	// Parse header
	headers := records[0]
	headerMap := make(map[string]int)
	for i, header := range headers {
		headerMap[strings.ToLower(strings.TrimSpace(header))] = i
	}

	var result []*events.Event
	for _, row := range records[1:] {
		event := events.NewEvent("ecucert")

		// Extract IP
		if idx, ok := headerMap["ip"]; ok && idx < len(row) {
			event.IP = row[idx]
		}

		// Extract timestamp
		if idx, ok := headerMap["timestamp"]; ok && idx < len(row) {
			event.EventDate = email.ParseDate(row[idx])
		}

		// Extract port
		for _, key := range []string{"port", "src_port"} {
			if idx, ok := headerMap[key]; ok && idx < len(row) {
				if portVal, err := strconv.Atoi(row[idx]); err == nil {
					event.Port = portVal
					break
				}
			}
		}

		// Extract URL
		for _, key := range []string{"url", "http_host", "hostname"} {
			if idx, ok := headerMap[key]; ok && idx < len(row) && row[idx] != "" {
				event.URL = row[idx]
				break
			}
		}

		// Extract ASN
		if idx, ok := headerMap["asn"]; ok && idx < len(row) && row[idx] != "" {
			event.AddEventDetail(&events.ASN{ASN: row[idx]})
		}

		// Extract target
		dstIP := ""
		dstPort := ""
		if idx, ok := headerMap["dst_ip"]; ok && idx < len(row) {
			dstIP = row[idx]
		}
		if idx, ok := headerMap["dst_port"]; ok && idx < len(row) {
			dstPort = row[idx]
		}
		if dstIP != "" {
			event.AddEventDetail(&events.Target{IP: dstIP, Port: dstPort})
		}

		// Determine event type
		eventTypeStr := ""
		for _, key := range []string{"vulnerabilidad", "incidente"} {
			if idx, ok := headerMap[key]; ok && idx < len(row) {
				eventTypeStr = strings.ToLower(row[idx])
				break
			}
		}

		if eventTypeStr == "" {
			return nil, common.NewNewTypeError("no event type key found")
		}

		if strings.Contains(eventTypeStr, "open") {
			service := ""
			parts := strings.Split(eventTypeStr, "_")
			if len(parts) > 1 {
				service = parts[len(parts)-1]
			}
			event.EventTypes = []events.EventType{events.NewOpen(service)}
		} else if strings.Contains(eventTypeStr, "bot") || strings.Contains(eventTypeStr, "ddos") {
			event.EventTypes = []events.EventType{events.NewBot("")}
		} else {
			event.EventTypes = []events.EventType{events.NewBot("")}
		}

		result = append(result, event)
	}

	return result, nil
}

// getValidCSV extracts CSV from attachment (handles .csv and .zip)
func getValidCSV(attachment email.EmailPart) ([]string, error) {
	// Check content-type in headers
	if contentTypes, ok := attachment.Headers["content-type"]; ok {
		for _, ct := range contentTypes {
			if strings.Contains(ct, ".csv") {
				if bodyStr, ok := attachment.Body.(string); ok {
					return strings.Split(bodyStr, "\n"), nil
				}
			} else if strings.Contains(ct, ".zip") {
				if bodyBytes, ok := attachment.Body.([]byte); ok {
					return getCSVFromZip(bodyBytes)
				}
			}
		}
	}

	// Check content-disposition in headers
	if contentDisps, ok := attachment.Headers["content-disposition"]; ok {
		for _, contentDisp := range contentDisps {
			if strings.Contains(contentDisp, ".csv") {
				if bodyStr, ok := attachment.Body.(string); ok {
					return strings.Split(bodyStr, "\n"), nil
				}
			} else if strings.Contains(contentDisp, ".zip") {
				if bodyBytes, ok := attachment.Body.([]byte); ok {
					return getCSVFromZip(bodyBytes)
				}
			}
		}
	}

	return nil, common.NewParserError("CSV attachment not found")
}

// getCSVFromZip extracts CSV from base64-encoded ZIP
func getCSVFromZip(rawBody []byte) ([]string, error) {
	// Try base64 decode first
	decoded, err := base64.StdEncoding.DecodeString(string(rawBody))
	if err != nil {
		// If decode fails, use raw bytes
		decoded = rawBody
	}

	zipReader, err := zip.NewReader(bytes.NewReader(decoded), int64(len(decoded)))
	if err != nil {
		return nil, err
	}

	for _, file := range zipReader.File {
		if strings.Contains(file.Name, ".csv") {
			rc, err := file.Open()
			if err != nil {
				continue
			}
			defer rc.Close()

			content, err := io.ReadAll(rc)
			if err != nil {
				continue
			}

			return cleanTerribleCSV(string(content)), nil
		}
	}

	return nil, common.NewParserError("no CSV file found in ZIP")
}

// cleanTerribleCSV handles malformed CSV with pipes in banner fields
func cleanTerribleCSV(data string) []string {
	bannerPattern := regexp.MustCompile(`\|.*\|`)
	var result []string

	for _, line := range strings.Split(data, "\n") {
		if bannerPattern.MatchString(line) {
			// Quote the banner field
			line = bannerPattern.ReplaceAllStringFunc(line, func(match string) string {
				return `"` + match + `"`
			})
		}
		result = append(result, line)
	}

	return result
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
