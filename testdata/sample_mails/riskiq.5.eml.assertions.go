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
	if event.IP != "=?utf-8?Q?TIME-SENSITIVE=20=E2=80=93=20Malicious=20Domain=20Name=20Re-direction=20Using=20Your=20Networks=20/=20Domainerschoice=20/=20DOMAIN=20pncbank[dot]cm/=20Incident=20ID=20No.:=2034399634?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?utf-8?Q?TIME-SENSITIVE=20=E2=80=93=20Malicious=20Domain=20Name=20Re-direction=20Using=20Your=20Networks=20/=20Domainerschoice=20/=20DOMAIN=20pncbank[dot]cm/=20Incident=20ID=20No.:=2034399634?=", event.IP)
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
