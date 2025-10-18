package assertions

import (
	"testing"

	"github.com/abusix/inbound-parsers/events"
)

func Assertions(t *testing.T, eventsList []*events.Event) {
	if len(eventsList) != 2 {
		t.Errorf("Expected 2 events, got %d", len(eventsList))
		return
	}

	// Event 0
	event := eventsList[0]
	if event.IP != "67.0.205.99" {
		t.Errorf("Event 0: Expected IP %q, got %q", "67.0.205.99", event.IP)
	}
	if event.Port != 61700 {
		t.Errorf("Event 0: Expected Port %d, got %d", 61700, event.Port)
	}
	if event.Parser != "acns" {
		t.Errorf("Event 0: Expected Parser %q, got %q", "acns", event.Parser)
	}
	if len(event.EventTypes) == 0 {
		t.Errorf("Event 0: Expected event type, got none")
	} else {
		eventType := fmt.Sprintf("%T", event.EventTypes[0])
		if !strings.Contains(eventType, "Copyright") {
			t.Errorf("Event 0: Expected event type containing %q, got %s", "Copyright", eventType)
		}
	}
	if len(event.EventDetails) != 6 {
		t.Errorf("Event 0: Expected 6 event details, got %d", len(event.EventDetails))
	}

	// Event 1
	event := eventsList[1]
	if event.IP != "67.0.205.99" {
		t.Errorf("Event 1: Expected IP %q, got %q", "67.0.205.99", event.IP)
	}
	if event.Port != 61700 {
		t.Errorf("Event 1: Expected Port %d, got %d", 61700, event.Port)
	}
	if event.Parser != "acns" {
		t.Errorf("Event 1: Expected Parser %q, got %q", "acns", event.Parser)
	}
	if len(event.EventTypes) == 0 {
		t.Errorf("Event 1: Expected event type, got none")
	} else {
		eventType := fmt.Sprintf("%T", event.EventTypes[0])
		if !strings.Contains(eventType, "Copyright") {
			t.Errorf("Event 1: Expected event type containing %q, got %s", "Copyright", eventType)
		}
	}
	if len(event.EventDetails) != 6 {
		t.Errorf("Event 1: Expected 6 event details, got %d", len(event.EventDetails))
	}

}
