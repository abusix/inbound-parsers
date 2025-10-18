package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// PythonAssertion represents the Python-generated assertion file structure
type PythonAssertion struct {
	Metadata     map[string]interface{} `json:"metadata"`
	ParserOutput ParserOutput           `json:"parser_output"`
}

// ParserOutput contains the parser results
type ParserOutput struct {
	Parser   string      `json:"parser"`
	Reporter string      `json:"reporter"`
	Rejected bool        `json:"rejected"`
	Events   []EventData `json:"events"`
}

// EventData represents a parsed event
type EventData struct {
	Date          *string                `json:"date"`
	Type          *string                `json:"type"`
	Parser        string                 `json:"parser"`
	ReportID      string                 `json:"report_id"`
	ReceivedDate  string                 `json:"received_date"`
	SendDate      string                 `json:"send_date"`
	SenderEmail   string                 `json:"sender_email"`
	RecipientEmail string                `json:"recipient_email"`
	Resources     map[string]interface{} `json:"resources"`
	EventTypes    []interface{}          `json:"event_types"`
}

// ComparisonResult tracks differences between Python and Go output
type ComparisonResult struct {
	File             string
	Match            bool
	ParserMismatch   bool
	PythonParser     string
	GoParser         string
	EventCountDiff   bool
	PythonEventCount int
	GoEventCount     int
	ResourceDiffs    []string
}

func main() {
	sampleDir := "testdata/sample_mails"

	// Get all Python assertion files
	pythonFiles, err := filepath.Glob(filepath.Join(sampleDir, "*.eml.assertions.json"))
	if err != nil {
		fmt.Printf("Error reading sample directory: %v\n", err)
		os.Exit(1)
	}

	sort.Strings(pythonFiles)
	fmt.Printf("Found %d Python assertion files\n\n", len(pythonFiles))

	matches := 0
	mismatches := 0
	errors := 0
	parserDiffs := 0
	eventCountDiffs := 0

	results := []ComparisonResult{}

	for idx, pythonPath := range pythonFiles {
		if (idx+1)%100 == 0 {
			fmt.Printf("Progress: %d/%d - Matches: %d, Mismatches: %d, Errors: %d\n",
				idx+1, len(pythonFiles), matches, mismatches, errors)
		}

		// Load Python assertion
		pythonData, err := loadPythonAssertion(pythonPath)
		if err != nil {
			fmt.Printf("ERROR loading Python assertion %s: %v\n", filepath.Base(pythonPath), err)
			errors++
			continue
		}

		// Get corresponding .eml file and run through Go parser
		emlPath := strings.TrimSuffix(pythonPath, ".assertions.json")

		result := ComparisonResult{
			File:             filepath.Base(emlPath),
			PythonParser:     pythonData.ParserOutput.Parser,
			PythonEventCount: len(pythonData.ParserOutput.Events),
		}

		// For now, just track the Python expected values
		// TODO: Run Go parser and compare
		result.Match = false
		result.ParserMismatch = true

		results = append(results, result)
		mismatches++

		if result.ParserMismatch {
			parserDiffs++
		}
	}

	fmt.Printf("\n=== Validation Results ===\n")
	fmt.Printf("Total files: %d\n", len(pythonFiles))
	fmt.Printf("Exact matches: %d\n", matches)
	fmt.Printf("Mismatches: %d\n", mismatches)
	fmt.Printf("Parser differences: %d\n", parserDiffs)
	fmt.Printf("Event count differences: %d\n", eventCountDiffs)
	fmt.Printf("Errors: %d\n", errors)

	// Generate report of parser implementations needed
	parserCounts := make(map[string]int)
	for _, result := range results {
		if result.PythonParser != "" {
			parserCounts[result.PythonParser]++
		}
	}

	fmt.Printf("\n=== Parser Implementation Status ===\n")
	fmt.Printf("Unique parsers: %d\n\n", len(parserCounts))

	// Sort parsers by count
	type parserCount struct {
		parser string
		count  int
	}
	var sortedParsers []parserCount
	for parser, count := range parserCounts {
		sortedParsers = append(sortedParsers, parserCount{parser, count})
	}
	sort.Slice(sortedParsers, func(i, j int) bool {
		return sortedParsers[i].count > sortedParsers[j].count
	})

	fmt.Printf("Top 20 parsers by email count:\n")
	for i, pc := range sortedParsers {
		if i >= 20 {
			break
		}
		fmt.Printf("  %3d emails: %s\n", pc.count, pc.parser)
	}

	// Write detailed report
	reportPath := ".claude/VALIDATION_REPORT.json"
	if err := writeJSONReport(reportPath, results); err != nil {
		fmt.Printf("ERROR writing report: %v\n", err)
	} else {
		fmt.Printf("\nDetailed report written to: %s\n", reportPath)
	}
}

func loadPythonAssertion(path string) (*PythonAssertion, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var assertion PythonAssertion
	if err := json.Unmarshal(data, &assertion); err != nil {
		return nil, err
	}

	return &assertion, nil
}

func writeJSONReport(path string, results []ComparisonResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}
