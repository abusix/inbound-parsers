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
	if event.IP != "[ EGP Cloudblock RBL / 1622661053.75675 ] [ RBL ] 178.128.112.15/32 (PTR: sekolahhosting.com.) added [ strike 5+: 90 day minimum ] [ <--- COMPROMISED HOST! ]" {
		t.Errorf("Event 0: Expected IP %q, got %q", "[ EGP Cloudblock RBL / 1622661053.75675 ] [ RBL ] 178.128.112.15/32 (PTR: sekolahhosting.com.) added [ strike 5+: 90 day minimum ] [ <--- COMPROMISED HOST! ]", event.IP)
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
