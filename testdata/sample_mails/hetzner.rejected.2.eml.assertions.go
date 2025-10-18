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
	if event.IP != "Re: Abuse Message [AbuseID:A98175:19]: AbuseBlacklist: [SpamCop (188.40.211.249) id:7187465162]=?UTF-8?Q?=F0=9F=87=BF=F0=9F=87=A6_Final_chance_to.." {
		t.Errorf("Event 0: Expected IP %q, got %q", "Re: Abuse Message [AbuseID:A98175:19]: AbuseBlacklist: [SpamCop (188.40.211.249) id:7187465162]=?UTF-8?Q?=F0=9F=87=BF=F0=9F=87=A6_Final_chance_to..", event.IP)
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
