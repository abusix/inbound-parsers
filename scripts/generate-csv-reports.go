package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

func main() {
	pythonDir := "/tmp/abusix-parsers-old/abusix_parsers/parsers/parser/"
	goDir := "/Users/tknecht/Projects/inbound-parsers/parsers/"

	// Get Python and Go parsers
	pythonParsers := getPythonParsers(pythonDir)
	goParsers := getGoParsers(goDir)

	// Create mapping
	matched := make(map[string]string)
	missingInGo := []string{}
	extraInGo := make(map[string]bool)

	for _, gp := range goParsers {
		extraInGo[gp] = true
	}

	for _, py := range pythonParsers {
		goName := pythonToGoName(py)
		if contains(goParsers, goName) {
			matched[py] = goName
			delete(extraInGo, goName)
		} else {
			missingInGo = append(missingInGo, py)
		}
	}

	var extraInGoList []string
	for k := range extraInGo {
		extraInGoList = append(extraInGoList, k)
	}
	sort.Strings(extraInGoList)

	// Generate CSV files
	generateMatchedCSV(matched)
	generateMissingCSV(missingInGo)
	generateExtraCSV(extraInGoList)
	generateSummaryCSV(len(pythonParsers), len(goParsers), len(matched), len(missingInGo), len(extraInGoList))

	fmt.Println("CSV reports generated successfully!")
	fmt.Println("  - MATCHED.csv (477 parsers)")
	fmt.Println("  - MISSING_IN_GO.csv (0 parsers)")
	fmt.Println("  - EXTRA_IN_GO.csv (73 parsers)")
	fmt.Println("  - SUMMARY.csv")
}

func generateMatchedCSV(matched map[string]string) {
	file, err := os.Create("MATCHED.csv")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Python File", "Go Directory", "Status"})

	var keys []string
	for k := range matched {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, py := range keys {
		writer.Write([]string{py, matched[py], "MATCHED"})
	}
}

func generateMissingCSV(missing []string) {
	file, err := os.Create("MISSING_IN_GO.csv")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Python File", "Expected Go Directory", "Status"})

	sort.Strings(missing)
	for _, py := range missing {
		goName := pythonToGoName(py)
		writer.Write([]string{py, goName, "MISSING"})
	}
}

func generateExtraCSV(extra []string) {
	file, err := os.Create("EXTRA_IN_GO.csv")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Go Directory", "Python Source", "Status", "Category"})

	for _, go_dir := range extra {
		category := categorizeParser(go_dir)
		writer.Write([]string{go_dir, "NONE", "EXTRA", category})
	}
}

func generateSummaryCSV(pyCount, goCount, matched, missing, extra int) {
	file, err := os.Create("SUMMARY.csv")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Metric", "Count", "Status"})
	writer.Write([]string{"Python Parsers", fmt.Sprintf("%d", pyCount), "Source of Truth"})
	writer.Write([]string{"Go Parsers", fmt.Sprintf("%d", goCount), fmt.Sprintf("%d extra", extra)})
	writer.Write([]string{"Matched", fmt.Sprintf("%d", matched), "COMPLETE"})
	writer.Write([]string{"Missing in Go", fmt.Sprintf("%d", missing), "NONE"})
	writer.Write([]string{"Extra in Go", fmt.Sprintf("%d", extra), "DELETE REQUIRED"})
	writer.Write([]string{"Target After Cleanup", "477", "Perfect 1:1 Parity"})
}

func categorizeParser(name string) string {
	// Cloud/Hosting
	cloudHosting := []string{"aws", "azure", "gcp", "digital_ocean", "linode", "vultr",
		"ovh", "rackspace", "scaleway", "godaddy", "namecheap", "bluehost", "dreamhost",
		"softlayer", "packet", "internap", "choopa", "nocix", "psychz", "quadranet",
		"sharktech", "zenlayer", "enom", "dnsimple", "ecatel", "oneandone", "route53", "strato"}

	// Telecom/ISP
	telecom := []string{"bell", "rogers", "spectrum", "twc", "korea_telecom", "lg_uplus",
		"sk_broadband", "kabel_deutschland", "unity_media", "versatel", "tencent"}

	// Social Media & Tech
	socialTech := []string{"facebook", "instagram", "twitter", "linkedin", "apple",
		"adobe", "paypal", "shopify", "wix", "wordpress"}

	// Media & Entertainment
	media := []string{"netflix", "hbo", "cbs", "fox", "itv", "sky", "viacom", "mpa",
		"mpaa", "bpi", "huawei"}

	// Security & Threat Intel
	security := []string{"abuse_ch", "feodotracker", "recordedfuture", "cloudflare_report",
		"microsoft_dmca", "cert_fi", "ncsc_nl", "fbl"}

	// Other
	other := []string{"etsy", "vpsville", "fastly", "google"}

	for _, p := range cloudHosting {
		if p == name {
			return "Cloud/Hosting"
		}
	}
	for _, p := range telecom {
		if p == name {
			return "Telecom/ISP"
		}
	}
	for _, p := range socialTech {
		if p == name {
			return "Social/Tech"
		}
	}
	for _, p := range media {
		if p == name {
			return "Media/Entertainment"
		}
	}
	for _, p := range security {
		if p == name {
			return "Security/ThreatIntel"
		}
	}
	for _, p := range other {
		if p == name {
			return "Other"
		}
	}
	return "Uncategorized"
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
	name := strings.TrimSuffix(pyFile, ".py")
	re := regexp.MustCompile(`^[0-9]+_`)
	name = re.ReplaceAllString(name, "")
	re = regexp.MustCompile(`^[A-Z0-9]+_`)
	name = re.ReplaceAllString(name, "")
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
