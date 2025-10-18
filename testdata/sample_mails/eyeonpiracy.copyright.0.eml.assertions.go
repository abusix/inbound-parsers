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
	if event.IP != "ISP Abuse [softsportstv.info.tm] : Demand for Immediate Take-Down Notice of Infringing Activity for CHARLTON LTD : ID notice be402225-2c8b-4ec4-93a6-97fb4e85af2e" {
		t.Errorf("Event 0: Expected IP %q, got %q", "ISP Abuse [softsportstv.info.tm] : Demand for Immediate Take-Down Notice of Infringing Activity for CHARLTON LTD : ID notice be402225-2c8b-4ec4-93a6-97fb4e85af2e", event.IP)
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
