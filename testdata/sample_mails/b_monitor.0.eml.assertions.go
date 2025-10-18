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
	if event.IP != "=?utf-8?B?W05vdGljZSBJRCAqWHhneTBtKl0g0J3QsNGA0YPRiNC10L3Q?= =?utf-8?B?uNC1INC/0YDQsNCyINC90LAg0YLQvtCy0LDRgNC90YvQtSDQt9C90LDQ?= =?utf-8?B?utC4ICJHb1BybyIg0L3QsCDRgdCw0LnRgtC1IGNvbXRyYWRpbmcudWEg?= =?utf-8?B?KDE3Mi42Ny43MC4zNSAvIEFTMTQwNjEgRGlnaXRhbE9jZWFuLCBMTEMp?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?utf-8?B?W05vdGljZSBJRCAqWHhneTBtKl0g0J3QsNGA0YPRiNC10L3Q?= =?utf-8?B?uNC1INC/0YDQsNCyINC90LAg0YLQvtCy0LDRgNC90YvQtSDQt9C90LDQ?= =?utf-8?B?utC4ICJHb1BybyIg0L3QsCDRgdCw0LnRgtC1IGNvbXRyYWRpbmcudWEg?= =?utf-8?B?KDE3Mi42Ny43MC4zNSAvIEFTMTQwNjEgRGlnaXRhbE9jZWFuLCBMTEMp?=", event.IP)
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
