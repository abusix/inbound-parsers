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
	if event.IP != "Copyright Notification - ATP Media [68a798527181a957d2e7f1d2,68a7985e7181a957d2e7f5e4,68a798827181a957d2e7f9f2,68a7988e7181a957d2e7fc5e - 796e428f-541a-48fc-8874-00ba9aef7286,106a505d-8cae-4b2d-888e-cf9a89e48337,3adb2246-3e33-450c-9fd0-4df346c9c1c8,b6c6db1c-258b-4232-b9f8-2c5cbfd04597]" {
		t.Errorf("Event 0: Expected IP %q, got %q", "Copyright Notification - ATP Media [68a798527181a957d2e7f1d2,68a7985e7181a957d2e7f5e4,68a798827181a957d2e7f9f2,68a7988e7181a957d2e7fc5e - 796e428f-541a-48fc-8874-00ba9aef7286,106a505d-8cae-4b2d-888e-cf9a89e48337,3adb2246-3e33-450c-9fd0-4df346c9c1c8,b6c6db1c-258b-4232-b9f8-2c5cbfd04597]", event.IP)
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
