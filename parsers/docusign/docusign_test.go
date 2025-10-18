package docusign

import (
	"testing"

	"github.com/abusix/inbound-parsers/pkg/email"
)

func TestParser_BasicPhishing(t *testing.T) {
	parser := NewParser()

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"from": {"abuse@docusign.com"},
			"date": {"Mon, 18 Oct 2025 12:00:00 +0000"},
		},
		Body: `DocuSign Phishing Report

URL: hxxp://malicious-site[.]com/fake-docusign
IP: 192.168.1.100

This is a phishing attempt impersonating DocuSign.
`,
	}

	events, err := parser.Parse(serializedEmail)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	event := events[0]

	// Check URL extraction and cleaning
	expectedURL := "http://malicious-site.com/fake-docusign"
	if event.URL != expectedURL {
		t.Errorf("Expected URL '%s', got '%s'", expectedURL, event.URL)
	}

	// Check IP extraction
	if event.IP != "192.168.1.100" {
		t.Errorf("Expected IP '192.168.1.100', got '%s'", event.IP)
	}

	// Check event types
	if len(event.EventTypes) != 2 {
		t.Fatalf("Expected 2 event types, got %d", len(event.EventTypes))
	}

	// Check phishing event type
	phishingFound := false
	trademarkFound := false
	for _, eventType := range event.EventTypes {
		if eventType.GetName() == "phishing" {
			phishingFound = true
		}
		if eventType.GetName() == "trademark" {
			trademarkFound = true
		}
	}

	if !phishingFound {
		t.Error("Expected phishing event type not found")
	}

	if !trademarkFound {
		t.Error("Expected trademark event type not found")
	}

	// Check parser name
	if event.Parser != "docusign" {
		t.Errorf("Expected parser 'docusign', got '%s'", event.Parser)
	}
}

func TestParser_NoBody(t *testing.T) {
	parser := NewParser()

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"from": {"abuse@docusign.com"},
			"date": {"Mon, 18 Oct 2025 12:00:00 +0000"},
		},
		Body: nil,
	}

	_, err := parser.Parse(serializedEmail)
	if err == nil {
		t.Fatal("Expected error for missing body, got nil")
	}
}

func TestParser_URLCleaning(t *testing.T) {
	parser := NewParser()

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"from": {"abuse@docusign.com"},
			"date": {"Mon, 18 Oct 2025 12:00:00 +0000"},
		},
		Body: `URL: hxxp://example[.]com/test
IP: 10.0.0.1`,
	}

	events, err := parser.Parse(serializedEmail)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	expectedURL := "http://example.com/test"
	if events[0].URL != expectedURL {
		t.Errorf("Expected URL '%s', got '%s'", expectedURL, events[0].URL)
	}
}

func TestParser_IPWithBrackets(t *testing.T) {
	parser := NewParser()

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"from": {"abuse@docusign.com"},
			"date": {"Mon, 18 Oct 2025 12:00:00 +0000"},
		},
		Body: `URL: http://test.com
IP: 192[.]168[.]1[.]1`,
	}

	events, err := parser.Parse(serializedEmail)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if events[0].IP != "192.168.1.1" {
		t.Errorf("Expected IP '192.168.1.1', got '%s'", events[0].IP)
	}
}
