package csirt_muni

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

	events, err := parser.Parse(serializedEmail)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(events) != 0 {
		t.Errorf("Expected 0 events for empty body, got %d", len(events))
	}
}

func TestParsePlainText(t *testing.T) {
	parser := NewParser()

	body := `Address: 192.168.1.1
Detection: Mon, 02 Jan 2006 15:04:05 -0700
Name: example.com
Incident: Incident type: SSH brute force attacks
`

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"subject": {"Test Subject"},
			"date":    {"Mon, 02 Jan 2006 15:04:05 -0700"},
		},
		Body:  body,
		Parts: []email.EmailPart{},
	}

	events, err := parser.Parse(serializedEmail)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	event := events[0]
	if event.IP != "192.168.1.1" {
		t.Errorf("Expected IP 192.168.1.1, got %s", event.IP)
	}

	if event.URL != "example.com" {
		t.Errorf("Expected URL example.com, got %s", event.URL)
	}

	if len(event.EventTypes) == 0 {
		t.Error("Expected event types to be set")
	}
}

func TestParseHTML(t *testing.T) {
	parser := NewParser()

	body := `<html>
<body>
the security team CSIRT-MU detected invol
Time of detection: Mon, 02 Jan 2006 15:04:05 -0700
IP address: 10.0.0.1
Domain name: test.com
Incident type: port scanning
</body>
</html>`

	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"subject": {"Test / English Subject"},
			"date":    {"Mon, 02 Jan 2006 15:04:05 -0700"},
		},
		Body: body,
		Parts: []email.EmailPart{
			{
				ContentType: "text/html",
				Body:        body,
			},
		},
	}

	events, err := parser.Parse(serializedEmail)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	event := events[0]
	if event.IP != "10.0.0.1" {
		t.Errorf("Expected IP 10.0.0.1, got %s", event.IP)
	}

	if event.URL != "test.com" {
		t.Errorf("Expected URL test.com, got %s", event.URL)
	}

	if len(event.EventTypes) == 0 {
		t.Error("Expected event types to be set")
	}
}
