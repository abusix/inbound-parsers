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
	if event.IP != "=?UTF-8?B?W0NFUlQuUEwgIzQwNDI3MDZdIFBvd2lhZG9taWVuaWUgQ0VSVCBQb2xza2Ev?= =?UTF-8?B?Q1NJUlQgTkFTSyBvIGRvc3TEmXBuZWogdXPFgnVkemUgIG1vZ8SFY2VqIHN0?= =?UTF-8?B?YW5vd2nEhyB6YWdyb8W8ZW5pZTogVW5pdHJvbmljcyBITUk=?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?UTF-8?B?W0NFUlQuUEwgIzQwNDI3MDZdIFBvd2lhZG9taWVuaWUgQ0VSVCBQb2xza2Ev?= =?UTF-8?B?Q1NJUlQgTkFTSyBvIGRvc3TEmXBuZWogdXPFgnVkemUgIG1vZ8SFY2VqIHN0?= =?UTF-8?B?YW5vd2nEhyB6YWdyb8W8ZW5pZTogVW5pdHJvbmljcyBITUk=?=", event.IP)
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
