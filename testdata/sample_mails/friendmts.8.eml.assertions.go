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
	if event.IP != "Copyright infringement notice : Incident ID 6726150 : Urgent live stream escalation URL http://forzatv.tk:8080/live/audrey/audrey/1935.ts - Sky Dillian Whyte vs Joseph Parker PPV, 28 July 2018 - IP address 178.128.48.170" {
		t.Errorf("Event 0: Expected IP %q, got %q", "Copyright infringement notice : Incident ID 6726150 : Urgent live stream escalation URL http://forzatv.tk:8080/live/audrey/audrey/1935.ts - Sky Dillian Whyte vs Joseph Parker PPV, 28 July 2018 - IP address 178.128.48.170", event.IP)
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
