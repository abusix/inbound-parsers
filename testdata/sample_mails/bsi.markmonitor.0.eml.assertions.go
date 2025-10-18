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
	if event.IP != "Fwd: [CERT-Bund#2018101828001399] =?UTF-8?Q?Betr=C3=BCgerische=20?=Website in Ihrer Rechtsordnung [MM #604241] (138.68.93.126 )" {
		t.Errorf("Event 0: Expected IP %q, got %q", "Fwd: [CERT-Bund#2018101828001399] =?UTF-8?Q?Betr=C3=BCgerische=20?=Website in Ihrer Rechtsordnung [MM #604241] (138.68.93.126 )", event.IP)
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
