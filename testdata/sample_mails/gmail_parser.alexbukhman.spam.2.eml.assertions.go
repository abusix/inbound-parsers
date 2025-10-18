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
	if event.IP != "=?UTF-8?Q?Re=3A_=E2=98=BA=F0=9F=98=98I_have_the_type_of_body_that_would_be_exc?= =?UTF-8?Q?iting_for_a_man_like_you_to_touch=2E?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?UTF-8?Q?Re=3A_=E2=98=BA=F0=9F=98=98I_have_the_type_of_body_that_would_be_exc?= =?UTF-8?Q?iting_for_a_man_like_you_to_touch=2E?=", event.IP)
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
