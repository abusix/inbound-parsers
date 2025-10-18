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
	if event.IP != "[Ticket#2024051603023351] Server - Remote Console (KVM) Appointment - AX41-NVMe #2357949 (88.99.52.49, 2a01:4f8:a1:1095::/64) [...]" {
		t.Errorf("Event 0: Expected IP %q, got %q", "[Ticket#2024051603023351] Server - Remote Console (KVM) Appointment - AX41-NVMe #2357949 (88.99.52.49, 2a01:4f8:a1:1095::/64) [...]", event.IP)
	}
	if event.Parser != "antipiracy_report" {
		t.Errorf("Event 0: Expected Parser %q, got %q", "antipiracy_report", event.Parser)
	}
	if len(event.EventTypes) == 0 {
		t.Errorf("Event 0: Expected event type, got none")
	} else {
		eventType := fmt.Sprintf("%T", event.EventTypes[0])
		if !strings.Contains(eventType, "Copyright") {
			t.Errorf("Event 0: Expected event type containing %q, got %s", "Copyright", eventType)
		}
	}
	if event.EventDate.IsZero() {
		t.Errorf("Event 0: Expected event date to be set")
	}

}
