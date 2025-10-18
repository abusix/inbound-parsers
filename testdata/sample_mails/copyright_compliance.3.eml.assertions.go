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
	if event.IP != "INFRINGEMENT OF ACTIVISION RIGHTS - m8n9k6q8.rocketcdn.me - Call of Duty: Warzone 2.0 - 3a49c72d-7042-49d1-adde-e5fb704fda17" {
		t.Errorf("Event 0: Expected IP %q, got %q", "INFRINGEMENT OF ACTIVISION RIGHTS - m8n9k6q8.rocketcdn.me - Call of Duty: Warzone 2.0 - 3a49c72d-7042-49d1-adde-e5fb704fda17", event.IP)
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
