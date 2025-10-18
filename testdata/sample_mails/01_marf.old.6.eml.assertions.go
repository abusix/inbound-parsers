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
	if event.IP != "=?utf-8?q?N=C4=9B=C5=BEn=C3=A9_=C5=A1perky_pro_d=C3=A1my=2C_plak?= =?utf-8?q?=C3=A1ty_Porsche_pro_p=C3=A1ny_a_na_z=C3=A1v=C4=9Br_sladk=C3=A1?= =?utf-8?q?_te=C4=8Dka_pro_v=C5=A1echny?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?utf-8?q?N=C4=9B=C5=BEn=C3=A9_=C5=A1perky_pro_d=C3=A1my=2C_plak?= =?utf-8?q?=C3=A1ty_Porsche_pro_p=C3=A1ny_a_na_z=C3=A1v=C4=9Br_sladk=C3=A1?= =?utf-8?q?_te=C4=8Dka_pro_v=C5=A1echny?=", event.IP)
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
