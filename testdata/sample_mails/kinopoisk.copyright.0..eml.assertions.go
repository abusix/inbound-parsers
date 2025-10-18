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
	if event.IP != "=?utf-8?Q?[COPYRIGHT-3620321]_=D0=98?= =?utf-8?Q?=D1=81=D0=BF=D0=BE=D0=BB=D1=8C?= =?utf-8?Q?=D0=B7=D0=BE=D0=B2=D0=B0=D0=BD=D0=B8?= =?utf-8?Q?=D0=B5_=D0=BC=D0=B0=D1=82=D0=B5=D1=80=D0=B8=D0=B0=D0=BB=D0=B0?= =?utf-8?Q?_=D0=9F=D0=B0=D1=82=D1=80=D0=B8=D0=BE=D1=82_=D0=BD?= =?utf-8?Q?=D0=B0_=D1=81=D0=B0=D0=B9=D1=82=D0=B5_htt?= =?utf-8?Q?p://bestkinotut.online?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?utf-8?Q?[COPYRIGHT-3620321]_=D0=98?= =?utf-8?Q?=D1=81=D0=BF=D0=BE=D0=BB=D1=8C?= =?utf-8?Q?=D0=B7=D0=BE=D0=B2=D0=B0=D0=BD=D0=B8?= =?utf-8?Q?=D0=B5_=D0=BC=D0=B0=D1=82=D0=B5=D1=80=D0=B8=D0=B0=D0=BB=D0=B0?= =?utf-8?Q?_=D0=9F=D0=B0=D1=82=D1=80=D0=B8=D0=BE=D1=82_=D0=BD?= =?utf-8?Q?=D0=B0_=D1=81=D0=B0=D0=B9=D1=82=D0=B5_htt?= =?utf-8?Q?p://bestkinotut.online?=", event.IP)
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
