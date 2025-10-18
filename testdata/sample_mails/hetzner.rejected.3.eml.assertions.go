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
	if event.IP != "Abuse Message [AbuseID:B31181:1C]: AbuseSpamvertised: [SpamCop (https://www.jeppeboys.co.za/) id:7213776284]Re: AIDEN VAN EYK" {
		t.Errorf("Event 0: Expected IP %q, got %q", "Abuse Message [AbuseID:B31181:1C]: AbuseSpamvertised: [SpamCop (https://www.jeppeboys.co.za/) id:7213776284]Re: AIDEN VAN EYK", event.IP)
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
