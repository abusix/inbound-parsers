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
	if event.IP != "Security System: IPs 142.93.33.203, 142.93.98.160, 143.198.138.46, 143.198.140.196, 143.198.140.6, 159.65.158.239, 159.65.162.79, 161.35.95.45, 167.99.128.171, 178.128.63.175, 192.241.226.74, 2604:a880:800:10::7a0 continuously send POST requests to our servers" {
		t.Errorf("Event 0: Expected IP %q, got %q", "Security System: IPs 142.93.33.203, 142.93.98.160, 143.198.138.46, 143.198.140.196, 143.198.140.6, 159.65.158.239, 159.65.162.79, 161.35.95.45, 167.99.128.171, 178.128.63.175, 192.241.226.74, 2604:a880:800:10::7a0 continuously send POST requests to our servers", event.IP)
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
