package domainoo

import (
	"testing"

	"github.com/abusix/inbound-parsers/pkg/email"
)

func TestParseTrademarkWithMultipleDomains(t *testing.T) {
	body := `Dear Sir/Madam,

We are writing to inform you about trademark infringement.

Our reference No: REF-12345

Domain names: example-trademark.com bad-domain.org fake-brand.net ; and another-domain.com

Please take action immediately.`

	subject := "Infringement of ACME trademark"

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"date":    {"Mon, 02 Jan 2006 15:04:05 -0700"},
			"subject": {subject},
		},
		Body: body,
	}

	parser := NewParser()
	events, err := parser.Parse(serializedEmail)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Should get 4 events (ignoring ";" and "and")
	if len(events) != 4 {
		t.Fatalf("Expected 4 events, got: %d", len(events))
	}

	expectedURLs := []string{
		"example-trademark.com",
		"bad-domain.org",
		"fake-brand.net",
		"another-domain.com",
	}

	for i, event := range events {
		if event.URL != expectedURLs[i] {
			t.Errorf("Event %d: Expected URL '%s', got: %s", i, expectedURLs[i], event.URL)
		}

		// Check event type
		if len(event.EventTypes) != 1 {
			t.Errorf("Event %d: Expected 1 event type, got: %d", i, len(event.EventTypes))
		}
		if event.EventTypes[0].GetName() != "trademark" {
			t.Errorf("Event %d: Expected event type 'trademark', got: %s", i, event.EventTypes[0].GetName())
		}

		// Check external ID
		if len(event.EventDetails) != 1 {
			t.Errorf("Event %d: Expected 1 event detail, got: %d", i, len(event.EventDetails))
		}
	}
}

func TestParseTrademarkWithSingleDomain(t *testing.T) {
	body := `Dear Sir/Madam,

We are writing to inform you about trademark infringement.

Our reference No: REF-67890

Domain name: single-domain.com

Please take action immediately.`

	subject := "Infringement of Brand XYZ trademark"

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"date":    {"Mon, 02 Jan 2006 15:04:05 -0700"},
			"subject": {subject},
		},
		Body: body,
	}

	parser := NewParser()
	events, err := parser.Parse(serializedEmail)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got: %d", len(events))
	}

	if events[0].URL != "single-domain.com" {
		t.Errorf("Expected URL 'single-domain.com', got: %s", events[0].URL)
	}

	// Check event type is trademark
	if len(events[0].EventTypes) > 0 {
		if events[0].EventTypes[0].GetName() != "trademark" {
			t.Errorf("Expected event type 'trademark', got: %s", events[0].EventTypes[0].GetName())
		}
	}
}

func TestParseTrademarkWithURLPattern(t *testing.T) {
	body := `Dear Sir/Madam,

We are writing to inform you about trademark infringement.

The domain registered-domain.com has been registered by your client.

Please take action immediately.`

	subject := "Trademark infringement notice"

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"date":    {"Mon, 02 Jan 2006 15:04:05 -0700"},
			"subject": {subject},
		},
		Body: body,
	}

	parser := NewParser()
	events, err := parser.Parse(serializedEmail)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got: %d", len(events))
	}

	if events[0].URL != "registered-domain.com" {
		t.Errorf("Expected URL 'registered-domain.com', got: %s", events[0].URL)
	}
}

func TestParseTrademarkWithURLField(t *testing.T) {
	body := `Dear Sir/Madam,

We are writing to inform you about trademark infringement.

URL: http://infringing-site.example.com

Please take action immediately.`

	subject := "Trademark infringement notice"

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"date":    {"Mon, 02 Jan 2006 15:04:05 -0700"},
			"subject": {subject},
		},
		Body: body,
	}

	parser := NewParser()
	events, err := parser.Parse(serializedEmail)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got: %d", len(events))
	}

	if events[0].URL != "http://infringing-site.example.com" {
		t.Errorf("Expected URL 'http://infringing-site.example.com', got: %s", events[0].URL)
	}
}

func TestParseNonTrademark(t *testing.T) {
	body := `This is a regular email about something else.`

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"date":    {"Mon, 02 Jan 2006 15:04:05 -0700"},
			"subject": {"Regular Email"},
		},
		Body: body,
	}

	parser := NewParser()
	_, err := parser.Parse(serializedEmail)

	if err == nil {
		t.Fatal("Expected error for non-trademark email, got nil")
	}

	if err.Error() != "new type error: regular email" {
		t.Errorf("Expected 'new type error: regular email', got: %s", err.Error())
	}
}

func TestParseTrademarkInBody(t *testing.T) {
	body := `Dear Sir/Madam,

This email is about a trademark violation.

Domain name: trademark-body.com

Please take action.`

	subject := "Urgent Notice"

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"date":    {"Mon, 02 Jan 2006 15:04:05 -0700"},
			"subject": {subject},
		},
		Body: body,
	}

	parser := NewParser()
	events, err := parser.Parse(serializedEmail)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got: %d", len(events))
	}

	if events[0].URL != "trademark-body.com" {
		t.Errorf("Expected URL 'trademark-body.com', got: %s", events[0].URL)
	}
}
