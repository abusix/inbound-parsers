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
	if event.IP != "=?UTF-8?B?0J/RgNC10LTRg9C/0YDQtdC20LTQtdC90LjQtSDQviDQvdC10LfQsNC60L4=?= =?UTF-8?B?0L3QvdC+0Lwg0LjRgdC/0L7Qu9GM0LfQvtCy0LDQvdC40Lgg0L7QsdGK0LU=?= =?UTF-8?B?0LrRgtC+0LIg0LDQstGC0L7RgNGB0LrQvtCz0L4g0L/RgNCw0LLQsC4=?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?UTF-8?B?0J/RgNC10LTRg9C/0YDQtdC20LTQtdC90LjQtSDQviDQvdC10LfQsNC60L4=?= =?UTF-8?B?0L3QvdC+0Lwg0LjRgdC/0L7Qu9GM0LfQvtCy0LDQvdC40Lgg0L7QsdGK0LU=?= =?UTF-8?B?0LrRgtC+0LIg0LDQstGC0L7RgNGB0LrQvtCz0L4g0L/RgNCw0LLQsC4=?=", event.IP)
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
