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
	if event.IP != "=?UTF-8?Q?Infringement_of_Microsoft_Corporation=E2=80=99s_Intellectu?= =?UTF-8?Q?al_Property_Rights_/_https://csgosmurfninja.com/fo?= =?UTF-8?Q?rza-horizon-5/=3Fwbraid=3DCjgKCAiAqbyNBhBJEigAWlMAjmOI?= =?UTF-8?Q?TPEjmevdwvx-gYw9JODgWMvzbXGf0Ge2nYNylPWzsGxbGgL0NA?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?UTF-8?Q?Infringement_of_Microsoft_Corporation=E2=80=99s_Intellectu?= =?UTF-8?Q?al_Property_Rights_/_https://csgosmurfninja.com/fo?= =?UTF-8?Q?rza-horizon-5/=3Fwbraid=3DCjgKCAiAqbyNBhBJEigAWlMAjmOI?= =?UTF-8?Q?TPEjmevdwvx-gYw9JODgWMvzbXGf0Ge2nYNylPWzsGxbGgL0NA?=", event.IP)
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
