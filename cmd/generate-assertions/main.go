package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

func main() {
	sampleDir := "testdata/sample_mails"

	generated := 0
	errors := 0
	rejected := 0
	skipped := 0

	// Get all .eml files
	files, err := filepath.Glob(filepath.Join(sampleDir, "*.eml"))
	if err != nil {
		fmt.Printf("Error reading sample directory: %v\n", err)
		os.Exit(1)
	}

	sort.Strings(files)
	fmt.Printf("Found %d sample email files\n\n", len(files))

	for idx, emailPath := range files {
		if (idx+1) % 100 == 0 {
			fmt.Printf("Progress: %d/%d - Generated: %d, Errors: %d, Rejected: %d, Skipped: %d\n",
				idx+1, len(files), generated, errors, rejected, skipped)
		}

		assertionPath := emailPath + ".assertions.go"

		// Skip if ends with .skip
		if strings.HasSuffix(emailPath, ".skip.eml") {
			skipped++
			continue
		}

		// Parse the email
		emailBytes, err := os.ReadFile(emailPath)
		if err != nil {
			fmt.Printf("ERROR reading %s: %v\n", filepath.Base(emailPath), err)
			errors++
			continue
		}

		// Load metadata if exists
		metadata := make(map[string]interface{})
		metaPath := emailPath + ".meta.json"
		if _, err := os.Stat(metaPath); err == nil {
			metaBytes, err := os.ReadFile(metaPath)
			if err == nil {
				json.Unmarshal(metaBytes, &metadata)
			}
		}

		serializedEmail, err := email.Parse(emailBytes)
		if err != nil {
			fmt.Printf("ERROR parsing %s: %v\n", filepath.Base(emailPath), err)
			errors++
			continue
		}

		// Try all parsers
		eventsList, parseErr := parsers.ParseEmail(serializedEmail, metadata)

		// Check for RejectError or IgnoreError
		isReject := false
		if parseErr != nil {
			if _, ok := parseErr.(*common.RejectError); ok {
				isReject = true
			}
		}

		if parseErr != nil {
			// Check if it's a rejection
			if isReject {
				rejected++
				if err := generateAssertionFile(assertionPath, nil, true); err != nil {
					fmt.Printf("ERROR generating assertion for %s: %v\n", filepath.Base(emailPath), err)
					errors++
				} else {
					generated++
				}
				continue
			}

			// Check if it's an ignore error - skip
			if _, ok := parseErr.(*common.IgnoreError); ok {
				skipped++
				continue
			}

			// Other errors
			fmt.Printf("ERROR parsing %s: %v\n", filepath.Base(emailPath), parseErr)
			errors++
			continue
		}

		if len(eventsList) == 0 {
			// Skip emails that produce no events
			skipped++
			continue
		}

		// Generate assertion file
		if err := generateAssertionFile(assertionPath, eventsList, false); err != nil {
			fmt.Printf("ERROR generating assertion for %s: %v\n", filepath.Base(emailPath), err)
			errors++
		} else {
			generated++
			if (generated % 10) == 0 {
				fmt.Printf("Generated %d assertions...\n", generated)
			}
		}
	}

	fmt.Printf("\n=== Final Results ===\n")
	fmt.Printf("Total emails processed: %d\n", len(files))
	fmt.Printf("Assertions generated: %d\n", generated)
	fmt.Printf("Rejected emails: %d\n", rejected)
	fmt.Printf("Errors: %d\n", errors)
	fmt.Printf("Skipped: %d\n", skipped)
}

func generateAssertionFile(path string, eventsList []*events.Event, rejected bool) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, "package assertions\n\n")
	fmt.Fprintf(f, "import (\n")
	fmt.Fprintf(f, "\t\"testing\"\n")
	fmt.Fprintf(f, "\n")
	fmt.Fprintf(f, "\t\"github.com/abusix/inbound-parsers/events\"\n")
	fmt.Fprintf(f, ")\n\n")
	fmt.Fprintf(f, "func Assertions(t *testing.T, eventsList []*events.Event) {\n")

	if rejected {
		fmt.Fprintf(f, "\t// This email should be rejected\n")
		fmt.Fprintf(f, "\tif len(eventsList) != 0 {\n")
		fmt.Fprintf(f, "\t\tt.Errorf(\"Expected 0 events (rejected), got %%d\", len(eventsList))\n")
		fmt.Fprintf(f, "\t}\n")
	} else {
		fmt.Fprintf(f, "\tif len(eventsList) != %d {\n", len(eventsList))
		fmt.Fprintf(f, "\t\tt.Errorf(\"Expected %d events, got %%d\", len(eventsList))\n", len(eventsList))
		fmt.Fprintf(f, "\t\treturn\n")
		fmt.Fprintf(f, "\t}\n\n")

		for i, event := range eventsList {
			if event == nil {
				continue
			}

			fmt.Fprintf(f, "\t// Event %d\n", i)
			fmt.Fprintf(f, "\tevent := eventsList[%d]\n", i)

			if event.IP != "" {
				fmt.Fprintf(f, "\tif event.IP != %q {\n", event.IP)
				fmt.Fprintf(f, "\t\tt.Errorf(\"Event %d: Expected IP %%q, got %%q\", %q, event.IP)\n", i, event.IP)
				fmt.Fprintf(f, "\t}\n")
			}

			if event.URL != "" {
				fmt.Fprintf(f, "\tif event.URL != %q {\n", event.URL)
				fmt.Fprintf(f, "\t\tt.Errorf(\"Event %d: Expected URL %%q, got %%q\", %q, event.URL)\n", i, event.URL)
				fmt.Fprintf(f, "\t}\n")
			}

			if event.Port != 0 {
				fmt.Fprintf(f, "\tif event.Port != %d {\n", event.Port)
				fmt.Fprintf(f, "\t\tt.Errorf(\"Event %d: Expected Port %%d, got %%d\", %d, event.Port)\n", i, event.Port)
				fmt.Fprintf(f, "\t}\n")
			}

			if event.Parser != "" {
				fmt.Fprintf(f, "\tif event.Parser != %q {\n", event.Parser)
				fmt.Fprintf(f, "\t\tt.Errorf(\"Event %d: Expected Parser %%q, got %%q\", %q, event.Parser)\n", i, event.Parser)
				fmt.Fprintf(f, "\t}\n")
			}

			if len(event.EventTypes) > 0 && event.EventTypes[0] != nil {
				eventType := event.EventTypes[0]
				typeName := fmt.Sprintf("%T", eventType)
				// Remove package prefix
				if idx := strings.LastIndex(typeName, "."); idx >= 0 {
					typeName = typeName[idx+1:]
				}
				// Remove pointer prefix
				typeName = strings.TrimPrefix(typeName, "*")

				fmt.Fprintf(f, "\tif len(event.EventTypes) == 0 {\n")
				fmt.Fprintf(f, "\t\tt.Errorf(\"Event %d: Expected event type, got none\")\n", i)
				fmt.Fprintf(f, "\t} else {\n")
				fmt.Fprintf(f, "\t\teventType := fmt.Sprintf(\"%%T\", event.EventTypes[0])\n")
				fmt.Fprintf(f, "\t\tif !strings.Contains(eventType, %q) {\n", typeName)
				fmt.Fprintf(f, "\t\t\tt.Errorf(\"Event %d: Expected event type containing %%q, got %%s\", %q, eventType)\n", i, typeName)
				fmt.Fprintf(f, "\t\t}\n")
				fmt.Fprintf(f, "\t}\n")
			}

			if event.EventDate != nil && !event.EventDate.IsZero() {
				fmt.Fprintf(f, "\tif event.EventDate.IsZero() {\n")
				fmt.Fprintf(f, "\t\tt.Errorf(\"Event %d: Expected event date to be set\")\n", i)
				fmt.Fprintf(f, "\t}\n")
			}

			if event.SenderEmail != "" {
				fmt.Fprintf(f, "\tif event.SenderEmail != %q {\n", event.SenderEmail)
				fmt.Fprintf(f, "\t\tt.Errorf(\"Event %d: Expected SenderEmail %%q, got %%q\", %q, event.SenderEmail)\n", i, event.SenderEmail)
				fmt.Fprintf(f, "\t}\n")
			}

			if len(event.EventDetails) > 0 {
				fmt.Fprintf(f, "\tif len(event.EventDetails) != %d {\n", len(event.EventDetails))
				fmt.Fprintf(f, "\t\tt.Errorf(\"Event %d: Expected %d event details, got %%d\", len(event.EventDetails))\n", i, len(event.EventDetails))
				fmt.Fprintf(f, "\t}\n")
			}

			fmt.Fprintf(f, "\n")
		}
	}

	fmt.Fprintf(f, "}\n")
	return nil
}
