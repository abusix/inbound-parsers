package dnsc

import (
	"testing"

	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

func TestParser_Fraud(t *testing.T) {
	parser := NewParser()

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"subject": {"Fraud alert for IP 192.168.1.100"},
			"date":    {"Mon, 18 Oct 2025 12:00:00 +0000"},
		},
		Body: `Fraud details
details -------------------------
https://example.com/fraud-report
---
Additional information`,
	}

	events, err := parser.Parse(serializedEmail)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	event := events[0]

	// Check event type
	if len(event.EventTypes) != 1 {
		t.Fatalf("Expected 1 event type, got %d", len(event.EventTypes))
	}

	if event.EventTypes[0].GetName() != "fraud" {
		t.Errorf("Expected event type 'fraud', got %s", event.EventTypes[0].GetName())
	}

	// Check IP extraction
	if event.IP != "192.168.1.100" {
		t.Errorf("Expected IP 192.168.1.100, got %s", event.IP)
	}

	// Check URL extraction
	if event.URL != "https://example.com/fraud-report" {
		t.Errorf("Expected URL https://example.com/fraud-report, got %s", event.URL)
	}

	// Check event date is set
	if event.EventDate == nil {
		t.Error("Expected event date to be set, got nil")
	}
}

func TestParser_CyberSecurityIncident(t *testing.T) {
	parser := NewParser()

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"subject": {"Cyber Security Incident - IP 10.0.0.1"},
			"date":    {"Mon, 18 Oct 2025 13:00:00 +0000"},
		},
		Body: `Incident report
details -------------------------
https://example.com/incident
---`,
	}

	events, err := parser.Parse(serializedEmail)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	event := events[0]

	// Check event type
	if len(event.EventTypes) != 1 {
		t.Fatalf("Expected 1 event type, got %d", len(event.EventTypes))
	}

	if event.EventTypes[0].GetName() != "malicious_activity" {
		t.Errorf("Expected event type 'malicious_activity', got %s", event.EventTypes[0].GetName())
	}

	// Check IP extraction
	if event.IP != "10.0.0.1" {
		t.Errorf("Expected IP 10.0.0.1, got %s", event.IP)
	}

	// Check URL extraction
	if event.URL != "https://example.com/incident" {
		t.Errorf("Expected URL https://example.com/incident, got %s", event.URL)
	}
}

func TestParser_UnknownType(t *testing.T) {
	parser := NewParser()

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"subject": {"Some other alert type"},
			"date":    {"Mon, 18 Oct 2025 12:00:00 +0000"},
		},
		Body: "Some body text",
	}

	_, err := parser.Parse(serializedEmail)
	if err == nil {
		t.Fatal("Expected NewTypeError, got nil")
	}

	if _, ok := err.(*common.NewTypeError); !ok {
		t.Errorf("Expected NewTypeError, got %T: %v", err, err)
	}
}

func TestParser_CaseInsensitive(t *testing.T) {
	parser := NewParser()

	// Test with uppercase FRAUD
	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"subject": {"FRAUD ALERT - 1.1.1.1"},
			"date":    {"Mon, 18 Oct 2025 12:00:00 +0000"},
		},
		Body: "details -------------------------\ntest\n---",
	}

	events, err := parser.Parse(serializedEmail)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	if events[0].EventTypes[0].GetName() != "fraud" {
		t.Errorf("Expected fraud event type, got %s", events[0].EventTypes[0].GetName())
	}
}

func TestParser_NoURLMarkers(t *testing.T) {
	parser := NewParser()

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"subject": {"Fraud alert - 8.8.8.8"},
			"date":    {"Mon, 18 Oct 2025 12:00:00 +0000"},
		},
		Body: "No markers here",
	}

	events, err := parser.Parse(serializedEmail)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	// URL should be empty if markers not found
	if events[0].URL != "" {
		t.Errorf("Expected empty URL, got %s", events[0].URL)
	}
}

func TestParser_NoIPInSubject(t *testing.T) {
	parser := NewParser()

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"subject": {"Fraud alert with no IP"},
			"date":    {"Mon, 18 Oct 2025 12:00:00 +0000"},
		},
		Body: "details -------------------------\ntest\n---",
	}

	events, err := parser.Parse(serializedEmail)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Should still succeed, just with empty IP
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	if events[0].IP != "" {
		t.Errorf("Expected empty IP, got %s", events[0].IP)
	}
}
