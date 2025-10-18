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
	if event.IP != "=?UTF-8?Q?Remo=C3=A7=C3=A3o_de_Conte=C3=BAdo_N=C3=A3o_Autoriz?= =?UTF-8?Q?ado_(Rastreamento:_#EFC1428318)?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?UTF-8?Q?Remo=C3=A7=C3=A3o_de_Conte=C3=BAdo_N=C3=A3o_Autoriz?= =?UTF-8?Q?ado_(Rastreamento:_#EFC1428318)?=", event.IP)
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

}
