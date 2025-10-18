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
	if event.IP != "[External Sender] =?ISO-8859-1?B?RXhwbG9pdC1ydW5zIGJ5IDgwLjg4Ljg4LjE0OSAvIG4=?= =?ISO-8859-1?B?byBhdXRvcmVwbHkgLyBub3JlcGx5ICAjSEUtREU6MDljM2ZkYzQ=?= =?ISO-8859-1?B?ZjM5NjYzNzYzIw==?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "[External Sender] =?ISO-8859-1?B?RXhwbG9pdC1ydW5zIGJ5IDgwLjg4Ljg4LjE0OSAvIG4=?= =?ISO-8859-1?B?byBhdXRvcmVwbHkgLyBub3JlcGx5ICAjSEUtREU6MDljM2ZkYzQ=?= =?ISO-8859-1?B?ZjM5NjYzNzYzIw==?=", event.IP)
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
