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
	if event.IP != "ISP Abuse [thevang.tv] : Demand for Immediate Take-Down Notice of Infringing Activity for VSTV (Vietnam Satellite Digital Television Company Limited) - K+ : ID notice 5e47d6cd-b131-4e3a-8845-18369ef16f91" {
		t.Errorf("Event 0: Expected IP %q, got %q", "ISP Abuse [thevang.tv] : Demand for Immediate Take-Down Notice of Infringing Activity for VSTV (Vietnam Satellite Digital Television Company Limited) - K+ : ID notice 5e47d6cd-b131-4e3a-8845-18369ef16f91", event.IP)
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
