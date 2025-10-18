package csis

import (
	"testing"

	"github.com/abusix/inbound-parsers/pkg/email"
)

func TestParserBasic(t *testing.T) {
	parser := NewParser()
	if parser == nil {
		t.Fatal("NewParser() returned nil")
	}

	// Test with empty email
	serializedEmail := &email.SerializedEmail{
		Headers: make(map[string][]string),
		Body:    "",
	}

	_, err := parser.Parse(serializedEmail)
	if err == nil {
		t.Error("Expected error for empty body, got nil")
	}
}

func TestParsePhishing(t *testing.T) {
	parser := NewParser()

	// Based on real CSIS phishing email
	body := `Abuse Type: Phishing
Date Abuse Reported: 2021-08-27 23:07
Targeted Brand: TESCO-NONBANK
Domain Name: thavere_._com
Obfuscated Full URL: https://thavere _._ com/oqfbvrqviladatsb9ludkuxflvxsjqsl0ao5ign4swbnqqlgsakdoxcokjfniqofniahkrd+ilcd
IPv4(s): 66.199.229.77, 181.214.238.65
ASN(s): 15149 | Access Integrated Technologies, Inc., 396073 | MAJESTIC-HOSTING-01

CSIS eCrime Unit is requesting your assistance in removing this fraudulent content.`

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"subject": {"[Phishing] Abuse Complaint: thavere.com"},
			"date":    {"Fri, 10 Sep 2021 23:22:40 +0000"},
			"from":    {"abuse-reporting@csis.dk"},
		},
		Body:  body,
		Parts: []email.EmailPart{},
	}

	events, err := parser.Parse(serializedEmail)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Should create 2 events (one per IP)
	if len(events) != 2 {
		t.Fatalf("Expected 2 events, got %d", len(events))
	}

	// Verify first event
	event1 := events[0]
	if event1.IP != "66.199.229.77" {
		t.Errorf("Expected IP 66.199.229.77, got %s", event1.IP)
	}

	// Verify URL deobfuscation
	expectedURL := "https://thavere.com/oqfbvrqviladatsb9ludkuxflvxsjqsl0ao5ign4swbnqqlgsakdoxcokjfniqofniahkrd+ilcd"
	if event1.URL != expectedURL {
		t.Errorf("Expected URL %s, got %s", expectedURL, event1.URL)
	}

	// Verify event type is Phishing
	if len(event1.EventTypes) == 0 {
		t.Error("Expected event types to be set")
	}

	// Verify ASN detail
	if len(event1.EventDetails) < 2 {
		t.Errorf("Expected at least 2 event details (ASN and Target), got %d", len(event1.EventDetails))
	}

	// Verify we have event details (ASN and Target)
	if len(event1.EventDetails) < 2 {
		t.Logf("Event details count: %d", len(event1.EventDetails))
		for i, detail := range event1.EventDetails {
			t.Logf("Detail %d type: %s", i, detail.GetType())
		}
	}

	// Verify second event
	event2 := events[1]
	if event2.IP != "181.214.238.65" {
		t.Errorf("Expected IP 181.214.238.65, got %s", event2.IP)
	}

	// Verify event date parsing
	if event1.EventDate == nil {
		t.Error("Expected event date to be set")
	}
}

func TestParseUnknownType(t *testing.T) {
	parser := NewParser()

	body := `Abuse Type: Unknown Type
Date Abuse Reported: 2021-08-27 23:07
Targeted Brand: BRAND
Obfuscated Full URL: https://example.com
IPv4(s): 192.0.2.1
ASN(s): 12345`

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"from": {"abuse-reporting@csis.dk"},
		},
		Body: body,
	}

	_, err := parser.Parse(serializedEmail)
	if err == nil {
		t.Error("Expected error for unknown abuse type, got nil")
	}
}
