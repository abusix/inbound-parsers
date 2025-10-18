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
	if event.IP != "194.88.143.8" {
		t.Errorf("Event 0: Expected IP %q, got %q", "194.88.143.8", event.IP)
	}
	if event.Port != 45413 {
		t.Errorf("Event 0: Expected Port %d, got %d", 45413, event.Port)
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

}
