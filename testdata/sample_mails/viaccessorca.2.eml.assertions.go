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
	if event.IP != "=?Windows-1252?Q?[c12ea6c9f28376a44059ece48d970a9494a848cf]_Notice_of_Inf?= =?Windows-1252?Q?ringement_of_the_5=E8me_journ=E9e_du_championnat_de_Fran?= =?Windows-1252?Q?ce_de_football_2022/2023_via_IP_address_185.135.157.156?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?Windows-1252?Q?[c12ea6c9f28376a44059ece48d970a9494a848cf]_Notice_of_Inf?= =?Windows-1252?Q?ringement_of_the_5=E8me_journ=E9e_du_championnat_de_Fran?= =?Windows-1252?Q?ce_de_football_2022/2023_via_IP_address_185.135.157.156?=", event.IP)
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
