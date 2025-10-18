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
	if event.IP != "Copyright Infringement on your site #RJ171579,RJ177273,RJ177930,RJ175255,RJ177407,RJ175534,RJ176539,RJ176337,RJ177721,RJ175779,RJ177621,RJ175997,RJ174131,RJ172667,RJ177123,RJ176689,RJ175870,RJ176086,RJ174279," {
		t.Errorf("Event 0: Expected IP %q, got %q", "Copyright Infringement on your site #RJ171579,RJ177273,RJ177930,RJ175255,RJ177407,RJ175534,RJ176539,RJ176337,RJ177721,RJ175779,RJ177621,RJ175997,RJ174131,RJ172667,RJ177123,RJ176689,RJ175870,RJ176086,RJ174279,", event.IP)
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
