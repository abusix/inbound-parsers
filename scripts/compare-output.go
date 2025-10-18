// Package main provides a comparison tool for V1 (Python) vs V2 (Go) parser output
// This validates that the Go migration produces byte-for-byte identical JSON output
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"

	"github.com/sergi/go-diff/diffmatchpatch"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <v1-output.json> <v2-output.json>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nCompares Python (V1) and Go (V2) parser output for identical JSON\n")
		os.Exit(1)
	}

	v1File := os.Args[1]
	v2File := os.Args[2]

	// Read V1 output
	v1Data, err := os.ReadFile(v1File)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading V1 file: %v\n", err)
		os.Exit(1)
	}

	// Read V2 output
	v2Data, err := os.ReadFile(v2File)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading V2 file: %v\n", err)
		os.Exit(1)
	}

	// Parse JSON
	var v1JSON, v2JSON interface{}
	if err := json.Unmarshal(v1Data, &v1JSON); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing V1 JSON: %v\n", err)
		os.Exit(1)
	}

	if err := json.Unmarshal(v2Data, &v2JSON); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing V2 JSON: %v\n", err)
		os.Exit(1)
	}

	// Compare
	if reflect.DeepEqual(v1JSON, v2JSON) {
		fmt.Println("✅ MATCH: Outputs are identical!")
		os.Exit(0)
	}

	// Outputs differ - show detailed diff
	fmt.Println("❌ MISMATCH: Outputs differ")
	fmt.Println()

	// Pretty print both for comparison
	v1Pretty, _ := json.MarshalIndent(v1JSON, "", "  ")
	v2Pretty, _ := json.MarshalIndent(v2JSON, "", "  ")

	// Show diff
	dmp := diffmatchpatch.New()
	diffs := dmp.DiffMain(string(v1Pretty), string(v2Pretty), false)

	fmt.Println("Differences:")
	fmt.Println(dmp.DiffPrettyText(diffs))

	os.Exit(1)
}
