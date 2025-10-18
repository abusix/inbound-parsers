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
	if event.IP != "37.201.82.97" {
		t.Errorf("Event 0: Expected IP %q, got %q", "37.201.82.97", event.IP)
	}
	if event.URL != "ed2k://|file|Ttc - The Teaching Company - Francis Colavita - Sensation, Perception, And The Aging Process.rar|174841479|DE91D7E5E745C2840207B8B47BEC504E|/" {
		t.Errorf("Event 0: Expected URL %q, got %q", "ed2k://|file|Ttc - The Teaching Company - Francis Colavita - Sensation, Perception, And The Aging Process.rar|174841479|DE91D7E5E745C2840207B8B47BEC504E|/", event.URL)
	}
	if event.Port != 7757 {
		t.Errorf("Event 0: Expected Port %d, got %d", 7757, event.Port)
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
