package assertions

import (
	"testing"

	"github.com/abusix/inbound-parsers/events"
)

func Assertions(t *testing.T, eventsList []*events.Event) {
	if len(eventsList) != 1 {
		t.Errorf("Expected 1 events, got %d", len(eventsList))
		return
	}

	// Event 0
	event := eventsList[0]
	if event.IP != "50.87.119.82" {
		t.Errorf("Event 0: Expected IP %q, got %q", "50.87.119.82", event.IP)
	}
	if event.Parser != "simple_url_report" {
		t.Errorf("Event 0: Expected Parser %q, got %q", "simple_url_report", event.Parser)
	}
	if len(event.EventTypes) == 0 {
		t.Errorf("Event 0: Expected event type, got none")
	} else {
		eventType := fmt.Sprintf("%T", event.EventTypes[0])
		if !strings.Contains(eventType, "Phishing") {
			t.Errorf("Event 0: Expected event type containing %q, got %s", "Phishing", eventType)
		}
	}
	if event.EventDate.IsZero() {
		t.Errorf("Event 0: Expected event date to be set")
	}

}
