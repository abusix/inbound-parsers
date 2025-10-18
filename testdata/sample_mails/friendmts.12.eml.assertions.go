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
	if event.IP != "=?utf-8?Q?Urgent=20Copyright=20Infringement=20Notice=20-=20Incident=20ID=2028807313=20-=20Urgent=20live=20stream=20escalation=20for=20URL=20http://video.fantasy.club/west/92abe14b-eadf-473f-b350-498f3ec0a267/720p/index1682021315.ts=20-=20The=20Union=20of=20European=20Football=20Associations=20(UEFA)=20-=20205.185.?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?utf-8?Q?Urgent=20Copyright=20Infringement=20Notice=20-=20Incident=20ID=2028807313=20-=20Urgent=20live=20stream=20escalation=20for=20URL=20http://video.fantasy.club/west/92abe14b-eadf-473f-b350-498f3ec0a267/720p/index1682021315.ts=20-=20The=20Union=20of=20European=20Football=20Associations=20(UEFA)=20-=20205.185.?=", event.IP)
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
