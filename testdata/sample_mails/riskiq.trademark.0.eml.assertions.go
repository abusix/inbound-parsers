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
	if event.IP != "=?utf-8?Q?TIME-SENSITIVE=20=E2=80=93=20Registered=20and=20Used=20in=20Bad=20Faith=20/=20NameCheap=2C=20Inc.=20/=20DOMAIN=20chasebankcreditcard[dot]us/=20Incident=20ID=20No.:=2036976690?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?utf-8?Q?TIME-SENSITIVE=20=E2=80=93=20Registered=20and=20Used=20in=20Bad=20Faith=20/=20NameCheap=2C=20Inc.=20/=20DOMAIN=20chasebankcreditcard[dot]us/=20Incident=20ID=20No.:=2036976690?=", event.IP)
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
