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
	if event.IP != "=?utf-8?Q?=D0=9F=D0=BE=D0=B2=D1=82=D0=BE=D1=80=D0=BD=D0=BE?= =?utf-8?Q?=D0=B5_=D1=83=D0=B2=D0=B5=D0=B4=D0=BE=D0=BC?= =?utf-8?Q?=D0=BB=D0=B5=D0=BD=D0=B8=D0=B5_=D0=BE_=D0=BD=D0=B0=D1=80=D1=83?= =?utf-8?Q?=D1=88=D0=B5=D0=BD=D0=B8=D0=B8_=D0=BF=D1=80?= =?utf-8?Q?=D0=BE=D0=B2=D0=B0=D0=B9=D0=B4=D0=B5=D1=80=D1=83/Repeated?= violation notice to hosting provider =?utf-8?Q?=D0=9C=2E=D0=92=D0=B8=D0=B4=D0=B5=D0=BE?= TiketId:878291" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?utf-8?Q?=D0=9F=D0=BE=D0=B2=D1=82=D0=BE=D1=80=D0=BD=D0=BE?= =?utf-8?Q?=D0=B5_=D1=83=D0=B2=D0=B5=D0=B4=D0=BE=D0=BC?= =?utf-8?Q?=D0=BB=D0=B5=D0=BD=D0=B8=D0=B5_=D0=BE_=D0=BD=D0=B0=D1=80=D1=83?= =?utf-8?Q?=D1=88=D0=B5=D0=BD=D0=B8=D0=B8_=D0=BF=D1=80?= =?utf-8?Q?=D0=BE=D0=B2=D0=B0=D0=B9=D0=B4=D0=B5=D1=80=D1=83/Repeated?= violation notice to hosting provider =?utf-8?Q?=D0=9C=2E=D0=92=D0=B8=D0=B4=D0=B5=D0=BE?= TiketId:878291", event.IP)
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
