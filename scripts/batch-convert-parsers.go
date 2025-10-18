package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

func main() {
	// Read the parser list
	listFile := "/tmp/python_parsers_477.txt"
	file, err := os.Open(listFile)
	if err != nil {
		fmt.Printf("Error opening list: %v\n", err)
		return
	}
	defer file.Close()

	// Already completed parsers
	completed := map[string]bool{
		"abusetrue_nl":    true,
		"abusix":          true,
		"acastano":        true,
		"adciberespaco":   true,
		"agouros":         true,
	}

	scanner := bufio.NewScanner(file)
	lineNum := 0
	successCount := 0
	failCount := 0
	skippedCount := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Parse parser name from line (format: "123→parser_name")
		parts := strings.Split(line, "→")
		if len(parts) != 2 {
			continue
		}
		parserName := strings.TrimSpace(parts[1])

		if completed[parserName] {
			skippedCount++
			continue
		}

		fmt.Printf("\n[%d/%d] Converting %s...\n", lineNum, 477, parserName)

		if err := convertParser(parserName); err != nil {
			fmt.Printf("  ❌ FAILED: %v\n", err)
			failCount++
		} else {
			fmt.Printf("  ✅ SUCCESS\n")
			successCount++
			completed[parserName] = true
		}
	}

	fmt.Printf("\n\n=== FINAL REPORT ===\n")
	fmt.Printf("Total parsers: 477\n")
	fmt.Printf("Already completed: %d\n", skippedCount)
	fmt.Printf("Successfully converted: %d\n", successCount)
	fmt.Printf("Failed: %d\n", failCount)
	fmt.Printf("Total done: %d\n", skippedCount+successCount)
	fmt.Printf("Remaining: %d\n", 477-(skippedCount+successCount))
}

func convertParser(name string) error {
	// Read Python source
	pythonPath := filepath.Join("/tmp/abusix-parsers-old/abusix_parsers/parsers/parser", name+".py")
	pythonCode, err := os.ReadFile(pythonPath)
	if err != nil {
		return fmt.Errorf("reading Python file: %w", err)
	}

	// Generate Go code
	goCode, err := generateGoCode(name, string(pythonCode))
	if err != nil {
		return fmt.Errorf("generating Go code: %w", err)
	}

	// Write to Go file
	goPath := filepath.Join("/Users/tknecht/Projects/inbound-parsers/parsers", name, name+".go")
	if err := os.WriteFile(goPath, []byte(goCode), 0644); err != nil {
		return fmt.Errorf("writing Go file: %w", err)
	}

	// Format the file
	cmd := exec.Command("gofmt", "-w", goPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("formatting: %w", err)
	}

	return nil
}

func generateGoCode(name, pythonCode string) (string, error) {
	// Extract key information from Python code
	eventTypes := extractEventTypes(pythonCode)
	hasIP := containsPattern(pythonCode, `event\['ip'\]|ip\s*=`)
	hasURL := containsPattern(pythonCode, `event\['url'\]|url\s*=`)
	hasDate := containsPattern(pythonCode, `event\['event_date'\]|event_date\s*=`)
	hasAttachment := containsPattern(pythonCode, `attachment|get_attachments`)
	usesRegex := containsPattern(pythonCode, `re\.search|re\.findall|re\.match|RE_`)

	// Build the Go code
	var sb strings.Builder

	// Package and imports
	sb.WriteString(fmt.Sprintf(`package %s

import (
	"github.com/abusix/inbound-parsers/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
`, name))

	if usesRegex {
		sb.WriteString("\t\"regexp\"\n")
	}
	if hasURL {
		sb.WriteString("\t\"strings\"\n")
	}

	sb.WriteString(")\n\n")

	// Add regex patterns if needed
	if usesRegex {
		patterns := extractRegexPatterns(pythonCode)
		if len(patterns) > 0 {
			sb.WriteString("var (\n")
			for i, pattern := range patterns {
				varName := fmt.Sprintf("pattern%d", i+1)
				sb.WriteString(fmt.Sprintf("\t%s = regexp.MustCompile(`%s`)\n", varName, escapePattern(pattern)))
			}
			sb.WriteString(")\n\n")
		}
	}

	// Parser struct
	sb.WriteString("type Parser struct{}\n\n")
	sb.WriteString("func NewParser() *Parser {\n\treturn &Parser{}\n}\n\n")

	// Parse method
	sb.WriteString("func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {\n")

	// Get body and subject
	sb.WriteString("\tbody, _ := common.GetBody(serializedEmail, false)\n")
	if containsPattern(pythonCode, "subject") {
		sb.WriteString("\tsubject, _ := common.GetSubject(serializedEmail, false)\n")
	}
	if hasAttachment {
		sb.WriteString("\tattachments := serializedEmail.GetAttachments()\n")
	}

	sb.WriteString("\n")

	// Create event
	sb.WriteString(fmt.Sprintf("\tevent := events.NewEvent(\"%s\")\n", name))

	// Set event types
	if len(eventTypes) > 0 {
		sb.WriteString("\tevent.EventTypes = []events.EventType{")
		for i, et := range eventTypes {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(et)
		}
		sb.WriteString("}\n")
	}

	// Add parsing logic based on patterns found
	sb.WriteString("\n\t// TODO: Extract data from body/subject/attachments\n")

	if hasIP {
		sb.WriteString("\t// Extract IP\n")
		sb.WriteString("\t// event.IP = extractedIP\n\n")
	}

	if hasURL {
		sb.WriteString("\t// Extract URL\n")
		sb.WriteString("\t// event.URL = extractedURL\n\n")
	}

	if hasDate {
		sb.WriteString("\t// Extract date\n")
		sb.WriteString("\t// if dateStr != \"\" {\n")
		sb.WriteString("\t//     event.EventDate = email.ParseDate(dateStr)\n")
		sb.WriteString("\t// }\n\n")
	}

	sb.WriteString("\treturn []*events.Event{event}, nil\n")
	sb.WriteString("}\n")

	return sb.String(), nil
}

func extractEventTypes(pythonCode string) []string {
	var types []string

	// Common mappings
	if containsPattern(pythonCode, "copyright|dmca|piracy") {
		types = append(types, "events.EventTypeCopyright")
	}
	if containsPattern(pythonCode, "phishing|phish") {
		types = append(types, "events.EventTypePhishing")
	}
	if containsPattern(pythonCode, "malware|virus|trojan") {
		types = append(types, "events.EventTypeMalware")
	}
	if containsPattern(pythonCode, "spam") {
		types = append(types, "events.EventTypeSpam")
	}
	if containsPattern(pythonCode, "botnet|bot") {
		types = append(types, "events.EventTypeBotnet")
	}
	if containsPattern(pythonCode, "scan|scanner|probe") {
		types = append(types, "events.EventTypeScanning")
	}
	if containsPattern(pythonCode, "bruteforce|brute") {
		types = append(types, "events.EventTypeBruteForce")
	}

	if len(types) == 0 {
		types = append(types, "events.EventTypeOther")
	}

	return types
}

func extractRegexPatterns(pythonCode string) []string {
	var patterns []string

	// Look for RE_ constants
	reConstPattern := regexp.MustCompile(`RE_\w+\s*=\s*r?["'](.+?)["']`)
	matches := reConstPattern.FindAllStringSubmatch(pythonCode, -1)
	for _, match := range matches {
		if len(match) > 1 {
			patterns = append(patterns, match[1])
		}
	}

	// Look for inline regex
	inlinePattern := regexp.MustCompile(`re\.(search|findall|match)\s*\(\s*r?["'](.+?)["']`)
	matches = inlinePattern.FindAllStringSubmatch(pythonCode, -1)
	for _, match := range matches {
		if len(match) > 2 {
			patterns = append(patterns, match[2])
		}
	}

	return patterns
}

func escapePattern(pattern string) string {
	// Escape backticks for Go raw strings
	return strings.ReplaceAll(pattern, "`", "` + \"`\" + `")
}

func containsPattern(text, pattern string) bool {
	re := regexp.MustCompile(`(?i)` + pattern)
	return re.MatchString(text)
}
