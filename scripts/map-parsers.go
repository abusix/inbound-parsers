package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

func main() {
	pythonDir := "/tmp/abusix-parsers-old/abusix_parsers/parsers/parser/"
	goDir := "/Users/tknecht/Projects/inbound-parsers/parsers/"

	// Get Python parsers
	pythonParsers := getPythonParsers(pythonDir)
	fmt.Printf("Python parsers found: %d\n\n", len(pythonParsers))

	// Get Go parsers
	goParsers := getGoParsers(goDir)
	fmt.Printf("Go parsers found: %d\n\n", len(goParsers))

	// Create mapping
	matched := make(map[string]string)      // python -> go
	missingInGo := []string{}               // python files with no Go dir
	extraInGo := make(map[string]bool)      // go dirs with no Python file

	// Initialize extraInGo with all Go parsers
	for _, gp := range goParsers {
		extraInGo[gp] = true
	}

	// Match Python parsers to Go parsers
	for _, py := range pythonParsers {
		goName := pythonToGoName(py)
		if contains(goParsers, goName) {
			matched[py] = goName
			delete(extraInGo, goName)
		} else {
			missingInGo = append(missingInGo, py)
		}
	}

	// Convert extraInGo map to sorted slice
	var extraInGoList []string
	for k := range extraInGo {
		extraInGoList = append(extraInGoList, k)
	}
	sort.Strings(extraInGoList)

	// Output results
	fmt.Printf("=== SUMMARY ===\n")
	fmt.Printf("MATCHED: %d parsers\n", len(matched))
	fmt.Printf("MISSING_IN_GO: %d parsers (need to create)\n", len(missingInGo))
	fmt.Printf("EXTRA_IN_GO: %d parsers (need to delete or verify)\n\n", len(extraInGoList))

	fmt.Printf("=== MATCHED PARSERS (%d) ===\n", len(matched))
	var matchedKeys []string
	for k := range matched {
		matchedKeys = append(matchedKeys, k)
	}
	sort.Strings(matchedKeys)
	for _, py := range matchedKeys {
		fmt.Printf("%s -> %s\n", py, matched[py])
	}

	fmt.Printf("\n=== MISSING IN GO (%d) - NEED TO CREATE ===\n", len(missingInGo))
	sort.Strings(missingInGo)
	for _, py := range missingInGo {
		goName := pythonToGoName(py)
		fmt.Printf("%s -> %s (MISSING)\n", py, goName)
	}

	fmt.Printf("\n=== EXTRA IN GO (%d) - NEED TO DELETE OR VERIFY ===\n", len(extraInGoList))
	for _, go_dir := range extraInGoList {
		fmt.Printf("%s (NO PYTHON SOURCE)\n", go_dir)
	}

	fmt.Printf("\n=== FINAL COUNT ===\n")
	fmt.Printf("Target: 477 parsers in both Python and Go\n")
	fmt.Printf("Python: %d parsers\n", len(pythonParsers))
	fmt.Printf("Go: %d parsers (excluding base, common)\n", len(goParsers))
	fmt.Printf("Matched: %d\n", len(matched))
	fmt.Printf("Missing in Go: %d\n", len(missingInGo))
	fmt.Printf("Extra in Go: %d\n", len(extraInGoList))
	fmt.Printf("\nExpected Go parsers after sync: %d (matched) + %d (missing) = %d\n",
		len(matched), len(missingInGo), len(matched)+len(missingInGo))
}

func getPythonParsers(dir string) []string {
	var parsers []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading Python directory: %v\n", err)
		os.Exit(1)
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".py") && entry.Name() != "__init__.py" {
			parsers = append(parsers, entry.Name())
		}
	}
	sort.Strings(parsers)
	return parsers
}

func getGoParsers(dir string) []string {
	var parsers []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading Go directory: %v\n", err)
		os.Exit(1)
	}

	for _, entry := range entries {
		if entry.IsDir() && entry.Name() != "base" && entry.Name() != "common" {
			parsers = append(parsers, entry.Name())
		}
	}
	sort.Strings(parsers)
	return parsers
}

func pythonToGoName(pyFile string) string {
	// Remove .py extension
	name := strings.TrimSuffix(pyFile, ".py")

	// Remove numeric prefixes with underscore: 001_, 02_, etc.
	re := regexp.MustCompile(`^[0-9]+_`)
	name = re.ReplaceAllString(name, "")

	// Remove alpha-numeric prefixes like ZX_
	re = regexp.MustCompile(`^[A-Z0-9]+_`)
	name = re.ReplaceAllString(name, "")

	// Convert dashes to underscores
	name = strings.ReplaceAll(name, "-", "_")

	return name
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
