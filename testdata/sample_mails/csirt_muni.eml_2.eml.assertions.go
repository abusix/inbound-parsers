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
	if event.IP != "=?UTF-8?B?W0NTSVJULU1VICM0MTk2OTRdIFDFmcOtc3R1cCBrIGhvbmV5cG90xa9tIHog?= =?UTF-8?B?SVAgYWRyZXN5IDEzOS41OS4zNi41NiAvIEFjY2VzcyB0byBob25leXBvdHMg?= =?UTF-8?B?ZnJvbSBJUCBhZGRyZXMgMTM5LjU5LjM2LjU2?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?UTF-8?B?W0NTSVJULU1VICM0MTk2OTRdIFDFmcOtc3R1cCBrIGhvbmV5cG90xa9tIHog?= =?UTF-8?B?SVAgYWRyZXN5IDEzOS41OS4zNi41NiAvIEFjY2VzcyB0byBob25leXBvdHMg?= =?UTF-8?B?ZnJvbSBJUCBhZGRyZXMgMTM5LjU5LjM2LjU2?=", event.IP)
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
