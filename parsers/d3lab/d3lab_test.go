package d3lab

import (
	"testing"

	"github.com/abusix/inbound-parsers/pkg/email"
)

func TestParsePhishingWithBlock(t *testing.T) {
	body := `Subject: Phishing Alert

We have detected a phishing attack using the following addresses (remove any square brackets):

http[.]example[.]com/phishing
192[.]0[.]2[.]1
https://malicious.example.org

Please take action immediately.`

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"date": {"Mon, 02 Jan 2006 15:04:05 -0700"},
		},
		Body: body,
	}

	parser := New()
	events, err := parser.Parse(serializedEmail)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(events) != 3 {
		t.Fatalf("Expected 3 events, got: %d", len(events))
	}

	// Check first event (URL)
	if events[0].URL != "http://example.com/phishing" {
		t.Errorf("Expected URL 'http://example.com/phishing', got: %s", events[0].URL)
	}

	// Check second event (IP)
	if events[1].IP != "192.0.2.1" {
		t.Errorf("Expected IP '192.0.2.1', got: %s", events[1].IP)
	}

	// Check third event (URL)
	if events[2].URL != "https://malicious.example.org" {
		t.Errorf("Expected URL 'https://malicious.example.org', got: %s", events[2].URL)
	}

	// Verify all events have phishing type
	for i, event := range events {
		if len(event.EventTypes) != 1 {
			t.Errorf("Event %d: Expected 1 event type, got: %d", i, len(event.EventTypes))
		}
		if event.EventTypes[0].GetName() != "phishing" {
			t.Errorf("Event %d: Expected event type 'phishing', got: %s", i, event.EventTypes[0].GetName())
		}
	}
}

func TestParseFallbackToSubject(t *testing.T) {
	body := `Subject: Phishing Alert

This is a phishing report without the specific marker.`

	subject := "http://phishing-site.example.com"

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"date":    {"Mon, 02 Jan 2006 15:04:05 -0700"},
			"subject": {subject},
		},
		Body: body,
	}

	parser := New()
	events, err := parser.Parse(serializedEmail)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got: %d", len(events))
	}

	if events[0].URL != subject {
		t.Errorf("Expected URL from subject '%s', got: %s", subject, events[0].URL)
	}
}

func TestParseNonPhishing(t *testing.T) {
	body := `This is not a phishing report.`

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"date":    {"Mon, 02 Jan 2006 15:04:05 -0700"},
			"subject": {"Regular Email"},
		},
		Body: body,
	}

	parser := New()
	_, err := parser.Parse(serializedEmail)

	if err == nil {
		t.Fatal("Expected error for non-phishing email, got nil")
	}
}

func TestParseEmptyBlock(t *testing.T) {
	body := `Subject: Phishing Alert

We have detected a phishing attack using the following addresses (remove any square brackets):

Please take action immediately.`

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"date":    {"Mon, 02 Jan 2006 15:04:05 -0700"},
			"subject": {"Phishing Alert"},
		},
		Body: body,
	}

	parser := New()
	events, err := parser.Parse(serializedEmail)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Empty block should fall through to using subject
	if len(events) != 1 {
		t.Fatalf("Expected 1 event (from subject fallback), got: %d", len(events))
	}

	if events[0].URL != "Phishing Alert" {
		t.Errorf("Expected URL 'Phishing Alert' from subject, got: %s", events[0].URL)
	}
}
