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
	if event.IP != "=?utf-8?B?W05vdGljZSBJRCAqZURDM05wKl0gc21hcnRoZWFkLmNvbS51?= =?utf-8?B?YSAoMTU3LjIzMC4xMTUuOTUpIOKAkyDQndCw0YDRg9GI0LXQvdC40LUg?= =?utf-8?B?0LjQvdGC0LXQu9C70LXQutGC0YPQsNC70YzQvdGL0YUg0L/RgNCw0LIg?= =?utf-8?B?LyBJbnRlbGxlY3R1YWwgcHJvcGVydHkgaW5mcmluZ2VtZW50IA==?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?utf-8?B?W05vdGljZSBJRCAqZURDM05wKl0gc21hcnRoZWFkLmNvbS51?= =?utf-8?B?YSAoMTU3LjIzMC4xMTUuOTUpIOKAkyDQndCw0YDRg9GI0LXQvdC40LUg?= =?utf-8?B?0LjQvdGC0LXQu9C70LXQutGC0YPQsNC70YzQvdGL0YUg0L/RgNCw0LIg?= =?utf-8?B?LyBJbnRlbGxlY3R1YWwgcHJvcGVydHkgaW5mcmluZ2VtZW50IA==?=", event.IP)
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
