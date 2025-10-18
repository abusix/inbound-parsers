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
	if event.IP != "=?UTF-8?Q?=E5=86=85=E5=AE=B9=E5=88=A0=E9=99=A4=E8=AF=B7=E6=B1=82_DOXXIN?= =?UTF-8?Q?G_(lr520.net)?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?UTF-8?Q?=E5=86=85=E5=AE=B9=E5=88=A0=E9=99=A4=E8=AF=B7=E6=B1=82_DOXXIN?= =?UTF-8?Q?G_(lr520.net)?=", event.IP)
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
