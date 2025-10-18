package cert_bz

import (
	"testing"

	"github.com/abusix/inbound-parsers/pkg/email"
)

func TestParser_NTPAmplification(t *testing.T) {
	parser := NewParser()

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"subject": {"NTP Amplification attack from 1.2.3.4"},
			"date":    {"Mon, 18 Oct 2025 12:00:00 +0000"},
		},
		Body: `Some body text
throughput
100|2025-10-18 12:00:00|flow123|1.2.3.4|5.6.7.8|123|500
more text`,
	}

	events, err := parser.Parse(serializedEmail)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Should return 2 events (one from log, one from subject)
	if len(events) != 2 {
		t.Fatalf("Expected 2 events, got %d", len(events))
	}

	// Check first event (from log data)
	if events[0].IP != "1.2.3.4" {
		t.Errorf("Expected IP 1.2.3.4, got %s", events[0].IP)
	}

	if len(events[0].EventDetails) != 1 {
		t.Errorf("Expected 1 event detail, got %d", len(events[0].EventDetails))
	}

	// Check second event (from subject)
	if events[1].IP != "1.2.3.4" {
		t.Errorf("Expected IP 1.2.3.4 from subject, got %s", events[1].IP)
	}
}

func TestParser_DDosTraffic(t *testing.T) {
	parser := NewParser()

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"subject": {"DDoS traffic from 10.0.0.1"},
			"date":    {"Mon, 18 Oct 2025 12:00:00 +0000"},
		},
		Body: "No throughput data",
	}

	events, err := parser.Parse(serializedEmail)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Should return 1 event (from subject only)
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	if events[0].IP != "10.0.0.1" {
		t.Errorf("Expected IP 10.0.0.1, got %s", events[0].IP)
	}

	if len(events[0].EventTypes) != 1 {
		t.Fatalf("Expected 1 event type, got %d", len(events[0].EventTypes))
	}

	if events[0].EventTypes[0].GetName() != "ddos" {
		t.Errorf("Expected event type 'ddos', got %s", events[0].EventTypes[0].GetName())
	}
}

func TestParser_UnknownType(t *testing.T) {
	parser := NewParser()

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"subject": {"Unknown attack from 1.2.3.4"},
			"date":    {"Mon, 18 Oct 2025 12:00:00 +0000"},
		},
		Body: "No throughput data",
	}

	_, err := parser.Parse(serializedEmail)
	if err == nil {
		t.Fatal("Expected NewTypeError, got nil")
	}

	if _, ok := err.(*NewTypeError); !ok {
		t.Errorf("Expected NewTypeError, got %T", err)
	}
}

func TestParser_NoIPInSubject(t *testing.T) {
	parser := NewParser()

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"subject": {"NTP Amplification attack"},
			"date":    {"Mon, 18 Oct 2025 12:00:00 +0000"},
		},
		Body: "No throughput data",
	}

	_, err := parser.Parse(serializedEmail)
	if err == nil {
		t.Fatal("Expected error for missing IP, got nil")
	}
}
