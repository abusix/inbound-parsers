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
	if event.IP != "=?utf-8?Q?Fwd=3A_=5BSpamCop_=28http=3A//action=2Eswirl=2Enl/h13vo?= =?utf-8?Q?i=2Ehggghlfjglw=2Ek=2Ek7rbh=2Ekc349=2Ejl=2Ek17=2Ehx=2Em76r2=2Ev?= =?utf-8?Q?c3x=2Ehgghv5=29_id=3A7255272727=5DUma_remessa_do_seu_pedido_=23?= =?utf-8?Q?29194772_est=C3=A1_dispon=C3=AD=2E=2E?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?utf-8?Q?Fwd=3A_=5BSpamCop_=28http=3A//action=2Eswirl=2Enl/h13vo?= =?utf-8?Q?i=2Ehggghlfjglw=2Ek=2Ek7rbh=2Ekc349=2Ejl=2Ek17=2Ehx=2Em76r2=2Ev?= =?utf-8?Q?c3x=2Ehgghv5=29_id=3A7255272727=5DUma_remessa_do_seu_pedido_=23?= =?utf-8?Q?29194772_est=C3=A1_dispon=C3=AD=2E=2E?=", event.IP)
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
