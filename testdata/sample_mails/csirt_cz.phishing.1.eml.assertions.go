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
	if event.IP != "Fwd: [Ticket#2021070928000399] informace o =?UTF-8?Q?bezpe=C4=8Dnostn=C3=ADm=20?=riziku KRPZ-54756/=?UTF-8?Q?T=C4=8C?=-2021-150581" {
		t.Errorf("Event 0: Expected IP %q, got %q", "Fwd: [Ticket#2021070928000399] informace o =?UTF-8?Q?bezpe=C4=8Dnostn=C3=ADm=20?=riziku KRPZ-54756/=?UTF-8?Q?T=C4=8C?=-2021-150581", event.IP)
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
