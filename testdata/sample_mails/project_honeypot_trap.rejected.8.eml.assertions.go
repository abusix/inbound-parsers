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
	if event.IP != "=?utf-8?B?44CK6ZSA5ZSu5rig6YGT5bu66K6+5LiO566h55CG44CL44CK5Lit5bGC77yITVRQ77yJ566h?= =?utf-8?B?55CG5oqA6IO95o+Q5Y2H44CLenlhY3huMg==?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?utf-8?B?44CK6ZSA5ZSu5rig6YGT5bu66K6+5LiO566h55CG44CL44CK5Lit5bGC77yITVRQ77yJ566h?= =?utf-8?B?55CG5oqA6IO95o+Q5Y2H44CLenlhY3huMg==?=", event.IP)
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
