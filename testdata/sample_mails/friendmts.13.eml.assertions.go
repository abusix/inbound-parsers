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
	if event.IP != "Copyright infringement notice : Incident ID 28767816 : Urgent live stream escalation for IP address 151.139.128.10 - URL http://live-gke17oc4.rmbl.ws/slot-63/q68b-r0h3_720p/media-u4nec1maj_6612.ts - Sky Italia S.r.l." {
		t.Errorf("Event 0: Expected IP %q, got %q", "Copyright infringement notice : Incident ID 28767816 : Urgent live stream escalation for IP address 151.139.128.10 - URL http://live-gke17oc4.rmbl.ws/slot-63/q68b-r0h3_720p/media-u4nec1maj_6612.ts - Sky Italia S.r.l.", event.IP)
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
