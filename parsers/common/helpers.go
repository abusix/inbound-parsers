// Package common provides helper functions for parsers
// This is a 100% exact Go translation of Python's parser_util functions
package common

import (
	"encoding/csv"
	"fmt"
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/pkg/email"
)

// GetBody returns the email body as a string
func GetBody(serializedEmail *email.SerializedEmail, throws bool) (string, error) {
	if serializedEmail.Body == nil {
		if throws {
			return "", fmt.Errorf("email body is empty")
		}
		return "", nil
	}

	switch body := serializedEmail.Body.(type) {
	case string:
		return body, nil
	case []byte:
		return string(body), nil
	default:
		if throws {
			return "", fmt.Errorf("unexpected body type: %T", body)
		}
		return "", nil
	}
}

// GetSubject returns the email subject
func GetSubject(serializedEmail *email.SerializedEmail, throws bool) (string, error) {
	if serializedEmail.Headers == nil {
		if throws {
			return "", fmt.Errorf("email headers are empty")
		}
		return "", nil
	}

	subject, ok := serializedEmail.Headers["subject"]
	if !ok || len(subject) == 0 {
		if throws {
			return "", fmt.Errorf("subject header not found")
		}
		return "", nil
	}

	return subject[0], nil
}

// GetFrom returns the email From address
func GetFrom(serializedEmail *email.SerializedEmail, throws bool) (string, error) {
	if serializedEmail.Headers == nil {
		if throws {
			return "", fmt.Errorf("email headers are empty")
		}
		return "", nil
	}

	from, ok := serializedEmail.Headers["from"]
	if !ok || len(from) == 0 {
		if throws {
			return "", fmt.Errorf("from header not found")
		}
		return "", nil
	}

	// Extract email address from "Name <email@example.com>" format
	fromAddr := from[0]
	if startIdx := strings.Index(fromAddr, "<"); startIdx != -1 {
		if endIdx := strings.Index(fromAddr[startIdx:], ">"); endIdx != -1 {
			return strings.ToLower(strings.TrimSpace(fromAddr[startIdx+1 : startIdx+endIdx])), nil
		}
	}

	return strings.ToLower(strings.TrimSpace(fromAddr)), nil
}

// FindStringWithoutMarkers finds text between two markers
func FindStringWithoutMarkers(text, startMarker, endMarker string) string {
	startIdx := strings.Index(text, startMarker)
	if startIdx == -1 {
		return ""
	}

	startIdx += len(startMarker)
	remaining := text[startIdx:]

	if endMarker == "" {
		// Default to line break
		endMarker = "\n"
		if strings.Contains(text, "\r\n") {
			endMarker = "\r\n"
		}
	}

	endIdx := strings.Index(remaining, endMarker)
	if endIdx == -1 {
		// If no end marker found, return the rest
		return strings.TrimSpace(remaining)
	}

	return strings.TrimSpace(remaining[:endIdx])
}

// GetNonEmptyLineAfter finds the first non-empty line after a marker
func GetNonEmptyLineAfter(text, marker string) string {
	startIdx := strings.Index(text, marker)
	if startIdx == -1 {
		return ""
	}

	remaining := text[startIdx+len(marker):]
	lines := strings.Split(remaining, "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			return trimmed
		}
	}

	return ""
}

// RemoveCarriageReturn removes \r characters from a string
func RemoveCarriageReturn(s string) string {
	return strings.ReplaceAll(s, "\r", "")
}

// GetBlockAround returns lines around a marker (used for table extraction)
// This is a 100% exact Go translation of Python's get_block_around function
func GetBlockAround(text, marker string) []string {
	lines := strings.Split(text, "\n")
	var block []string
	var result []string
	foundStart := false

	for _, line := range lines {
		if strings.Contains(line, marker) {
			foundStart = true
			// Yield the accumulated block first
			for _, b := range block {
				result = append(result, b)
			}
		}
		if foundStart {
			// Stop at empty line
			if strings.TrimSpace(line) == "" {
				break
			}
			result = append(result, line)
		} else if strings.TrimSpace(line) == "" {
			// Reset block on empty line
			block = nil
		} else {
			// Accumulate non-empty lines before marker
			block = append(block, line)
		}
	}

	return result
}

// FindFirstAttachmentWithMimeType finds the first attachment with a given extension
func FindFirstAttachmentWithMimeType(serializedEmail *email.SerializedEmail, extension string) (string, error) {
	for _, part := range serializedEmail.Parts {
		if part.Headers != nil {
			if disposition, ok := part.Headers["content-disposition"]; ok {
				for _, disp := range disposition {
					if strings.Contains(strings.ToLower(disp), extension) {
						switch body := part.Body.(type) {
						case string:
							return body, nil
						case []byte:
							return string(body), nil
						default:
							return "", fmt.Errorf("unexpected part body type: %T", body)
						}
					}
				}
			}
		}
	}
	return "", fmt.Errorf("attachment with extension '%s' not found", extension)
}

// ExtractHTMLTableAsCSV extracts an HTML table and converts it to CSV
func ExtractHTMLTableAsCSV(html string) ([]string, error) {
	// Simple implementation - extract text between <tr> tags
	var rows []string

	// Remove HTML tags and extract table data
	html = strings.ReplaceAll(html, "<th", "<td")
	html = strings.ReplaceAll(html, "</th", "</td")

	// Find all rows
	rowPattern := regexp.MustCompile(`<tr[^>]*>(.*?)</tr>`)
	rowMatches := rowPattern.FindAllStringSubmatch(html, -1)

	for _, rowMatch := range rowMatches {
		if len(rowMatch) > 1 {
			// Extract cells
			cellPattern := regexp.MustCompile(`<td[^>]*>(.*?)</td>`)
			cellMatches := cellPattern.FindAllStringSubmatch(rowMatch[1], -1)

			var cells []string
			for _, cellMatch := range cellMatches {
				if len(cellMatch) > 1 {
					// Clean up cell text
					cell := regexp.MustCompile(`<[^>]+>`).ReplaceAllString(cellMatch[1], "")
					cell = strings.TrimSpace(cell)
					cells = append(cells, cell)
				}
			}

			if len(cells) > 0 {
				rows = append(rows, strings.Join(cells, ","))
			}
		}
	}

	if len(rows) == 0 {
		return nil, fmt.Errorf("no table rows found in HTML")
	}

	return rows, nil
}

// ParseCSVString parses a CSV string into a slice of maps
func ParseCSVString(csvData string) ([]map[string]string, error) {
	reader := csv.NewReader(strings.NewReader(csvData))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no CSV data found")
	}

	headers := records[0]
	var result []map[string]string

	for i := 1; i < len(records); i++ {
		row := make(map[string]string)
		for j, value := range records[i] {
			if j < len(headers) {
				row[headers[j]] = value
			}
		}
		result = append(result, row)
	}

	return result, nil
}

// FindString finds text between startMarker and endMarker (including markers)
func FindString(text, startMarker, endMarker string) string {
	startIdx := strings.Index(text, startMarker)
	if startIdx == -1 {
		return ""
	}

	remaining := text[startIdx:]
	endIdx := strings.Index(remaining, endMarker)
	if endIdx == -1 {
		return ""
	}

	// Include both markers in the result
	return remaining[:endIdx+len(endMarker)]
}

// GetContinuousLinesUntilEmptyLine returns lines from start marker until an empty line is detected
// Ignores empty lines before the first non-empty line
func GetContinuousLinesUntilEmptyLine(text, startMarker string) []string {
	idx := strings.Index(text, startMarker)
	if idx == -1 {
		return nil
	}

	// Find the next newline after the marker
	remaining := text[idx:]
	newlineIdx := strings.Index(remaining, "\n")
	if newlineIdx != -1 {
		remaining = remaining[newlineIdx:]
	}

	lines := strings.Split(remaining, "\n")
	var result []string
	foundNonEmpty := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip empty lines before first non-empty line
		if !foundNonEmpty && trimmed == "" {
			continue
		}

		// Stop at empty line after we've found non-empty content
		if foundNonEmpty && trimmed == "" {
			break
		}

		foundNonEmpty = true
		result = append(result, line)
	}

	return result
}

// ParsePort converts a string to an integer port number
func ParsePort(portStr string) (int, error) {
	portStr = strings.TrimSpace(portStr)
	if portStr == "" {
		return 0, fmt.Errorf("empty port string")
	}

	var port int
	_, err := fmt.Sscanf(portStr, "%d", &port)
	if err != nil {
		return 0, fmt.Errorf("invalid port: %w", err)
	}

	if port < 0 || port > 65535 {
		return 0, fmt.Errorf("port out of range: %d", port)
	}

	return port, nil
}

// CleanURL cleans a URL string by replacing obfuscation patterns
// This is a 100% exact Go translation of Python's clean_url function
func CleanURL(url string) string {
	url = strings.ReplaceAll(url, " ", "")
	url = strings.ReplaceAll(url, "[.]", ".")
	url = strings.ReplaceAll(url, "(.)", ".")
	url = strings.ReplaceAll(url, "[dot]", ".")
	url = strings.ReplaceAll(url, "(dot)", ".")
	url = strings.ReplaceAll(url, "[:]", ":")
	url = strings.ReplaceAll(url, "(:)", ":")
	url = strings.ReplaceAll(url, "hxxp", "http")
	url = strings.ReplaceAll(url, "hXXp", "http")
	url = strings.ReplaceAll(url, "http ", "http://")
	url = strings.ReplaceAll(url, "https ", "https://")
	return url
}

// MapServiceStrings maps service identifiers to standardized names
func MapServiceStrings(service string) string {
	service = strings.ToLower(strings.TrimSpace(service))

	// Map common service names
	switch service {
	case "accessible-http", "directory listing":
		return service
	case "scan":
		return "port_scan"
	default:
		return service
	}
}

// FindValueFromKeylist searches for a value in a map using a list of keys
func FindValueFromKeylist(keys []string, entry map[string]string) string {
	for _, key := range keys {
		if val, ok := entry[key]; ok {
			return val
		}
	}
	return ""
}

// ParseInt converts a string to an integer
func ParseInt(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty string")
	}

	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	if err != nil {
		return 0, fmt.Errorf("invalid integer: %w", err)
	}

	return n, nil
}

// GetLineAfter returns the nth line after a marker (1-indexed)
func GetLineAfter(base, marker string, nrLines int) string {
	idx := strings.Index(base, marker)
	if idx == -1 {
		return ""
	}

	remaining := base[idx:]
	lines := strings.Split(remaining, "\n")

	// Skip the line containing the marker
	if nrLines >= 0 && nrLines < len(lines)-1 {
		return lines[nrLines]
	}

	return ""
}

// GetBlockAroundWithContinueUntil returns lines around a marker until a continue_until marker is found
// This is a 100% exact Go translation of Python's get_block_around with continue_until parameter
func GetBlockAroundWithContinueUntil(text, marker, continueUntil string) ([]string, error) {
	lines := strings.Split(text, "\n")
	var block []string
	var result []string
	foundStart := false

	for _, line := range lines {
		if strings.Contains(line, marker) {
			foundStart = true
			// Yield the accumulated block first
			for _, b := range block {
				result = append(result, b)
			}
		}
		if foundStart {
			if continueUntil != "" && strings.Contains(line, continueUntil) {
				// Found the continue_until marker, stop here
				return result, nil
			}
			result = append(result, line)
		} else if strings.TrimSpace(line) == "" {
			// Reset block on empty line
			block = nil
		} else {
			// Accumulate non-empty lines before marker
			block = append(block, line)
		}
	}

	if continueUntil != "" {
		return nil, fmt.Errorf("continue_until was set to '%s' but did not match any line", continueUntil)
	}

	return result, nil
}

// OneLineColonKeyValueGenerator parses key-value pairs from text
// This is a 100% exact Go translation of Python's one_line_colon_key_value_generator
// It matches lines like "Key: value" where value doesn't start with \r and ends at \n
func OneLineColonKeyValueGenerator(text string) map[string][]string {
	// Regex: ([\w \']+): +(.+?)\r?\n
	// Matches: key (word chars, spaces, apostrophes) : space+ value (not starting with \r) ending with optional \r\n
	pattern := regexp.MustCompile(`([\w \']+): +(.+?)\r?\n`)
	matches := pattern.FindAllStringSubmatch(text, -1)

	result := make(map[string][]string)
	for _, match := range matches {
		if len(match) >= 3 {
			key := strings.TrimSpace(match[1])
			value := strings.TrimSpace(match[2])
			result[key] = append(result[key], value)
		}
	}

	return result
}

// IncidentTypeToEventType converts an incident type string to an EventType
// This is a 100% exact Go translation of Python's incident_type_to_event_type
// It's the reverse of event_to_incident_type from ahq inbound
// Import events package where this is used
func IncidentTypeToEventType(name string) string {
	// Normalize the name
	typeCandidate := strings.ReplaceAll(name, "-", "_")
	typeCandidate = strings.ReplaceAll(typeCandidate, " ", "_")
	typeCandidate = strings.ToLower(typeCandidate)

	// Direct mappings based on event_type_by_name from Python
	switch typeCandidate {
	case "spam":
		return "spam"
	case "phishing":
		return "phishing"
	case "bot", "bot_infection":
		return "bot"
	case "copyright":
		return "copyright"
	case "ddos":
		return "ddos"
	case "fraud":
		return "fraud"
	case "login_attack":
		return "login_attack"
	case "malware_hosting":
		return "malware_hosting"
	case "malware":
		return "malware"
	case "web_hack":
		return "web_hack"
	case "blacklist":
		return "blacklist"
	case "compromised_microsoft_exchange":
		return "compromised_microsoft_exchange"
	case "compromised_website":
		return "compromised_website"
	case "compromised_server":
		return "compromised_server"
	case "compromised_account":
		return "compromised_account"
	case "ddos_amplification":
		return "ddos_amplification"
	case "outdated_dnssec":
		return "outdated_dnssec"
	case "ssl_poodle":
		return "ssl_poodle"
	case "ssl_freak":
		return "ssl_freak"
	case "cve":
		return "cve"
	case "ip_spoof":
		return "ip_spoof"
	case "port_scan":
		return "port_scan"
	case "exploit":
		return "exploit"
	case "trademark":
		return "trademark"
	case "illegal_advertisement":
		return "illegal_advertisement"
	case "malicious_activity":
		return "malicious_activity"
	case "spamvertised":
		return "spamvertised"
	case "dns_blocklist":
		return "dns_blocklist"
	case "child_abuse":
		return "child_abuse"
	case "doxing":
		return "doxing"
	case "web_crawler":
		return "web_crawler"
	case "rogue_dns":
		return "rogue_dns"
	case "defacement":
		return "defacement"
	case "unknown":
		return "unknown"
	case "violence":
		return "violence"
	case "propaganda":
		return "propaganda"
	case "auth_failure":
		return "auth_failure"
	case "backdoor":
		return "backdoor"
	}

	// Handle "open_*" patterns
	if strings.HasPrefix(typeCandidate, "open") {
		return "open"
	}

	return ""
}

// GetBlockAfter gets a non-empty block of text after a start marker
// This is a 100% exact Go translation of Python's get_block_after function
// It searches from the first empty line after the start marker until the next empty line
func GetBlockAfter(base, startMarker string) []string {
	foundStart := false
	foundEmpty := false
	foundData := false
	var result []string

	for _, line := range strings.Split(base, "\n") {
		trimmed := strings.TrimSpace(line)

		if strings.Contains(trimmed, startMarker) {
			foundStart = true
		} else if foundStart && !foundData && trimmed == "" {
			foundEmpty = true
		} else if foundStart && foundEmpty {
			foundData = true
			if trimmed == "" {
				// Stop at next empty line
				break
			}
			result = append(result, trimmed)
		}
	}

	return result
}
