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
	if event.IP != "FW: Issue 31188945: Cryptocurrency investment scam at hxxp://meansmoveforward[.]com/9iw35llmatt3b3kyy2hm6f5ce9l6f8y1rgp2y30ro938s03kyelhqvo673s6j81jj031jso3277it9vu.E6X2YTNDQBJTVV21YKWA6AYASLSMLL394I145VMNT8?XqsCFqmXyYmh=vcTPqmXkndZl19qtf0r00sn1601k6rs0z1" {
		t.Errorf("Event 0: Expected IP %q, got %q", "FW: Issue 31188945: Cryptocurrency investment scam at hxxp://meansmoveforward[.]com/9iw35llmatt3b3kyy2hm6f5ce9l6f8y1rgp2y30ro938s03kyelhqvo673s6j81jj031jso3277it9vu.E6X2YTNDQBJTVV21YKWA6AYASLSMLL394I145VMNT8?XqsCFqmXyYmh=vcTPqmXkndZl19qtf0r00sn1601k6rs0z1", event.IP)
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
