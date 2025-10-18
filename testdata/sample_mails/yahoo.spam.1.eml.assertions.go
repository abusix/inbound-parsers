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
	if event.IP != "=?UTF-8?Q?Fw:_S=C2=ADt=C2=ADr=C2=ADok=C2=ADes_c=C2=ADa?= =?UTF-8?Q?=C2=ADn_b=C2=ADe_p=C2=ADre=C2=ADven=C2=ADta=C2=ADb?= =?UTF-8?Q?le._G=C2=ADe=C2=ADt_y=C2=ADou=C2=ADr_s=C2=ADc?= =?UTF-8?Q?=C2=ADre=C2=ADen=C2=ADin=C2=ADg_t=C2=ADo=C2=ADda=C2=ADy?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?UTF-8?Q?Fw:_S=C2=ADt=C2=ADr=C2=ADok=C2=ADes_c=C2=ADa?= =?UTF-8?Q?=C2=ADn_b=C2=ADe_p=C2=ADre=C2=ADven=C2=ADta=C2=ADb?= =?UTF-8?Q?le._G=C2=ADe=C2=ADt_y=C2=ADou=C2=ADr_s=C2=ADc?= =?UTF-8?Q?=C2=ADre=C2=ADen=C2=ADin=C2=ADg_t=C2=ADo=C2=ADda=C2=ADy?=", event.IP)
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
