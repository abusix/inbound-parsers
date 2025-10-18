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
	if event.IP != "=?UTF-8?B?W2VhaXMjNTU3NzM0XSDQoNC+0YHQutC+0LzQvdCw0LTQt9C+0YAg0LjQvdGE0L7RgNC80LjRgNGD0LXRgi90aGUgUm9zY29tbmFkem9yIGlzIGluZm9ybWluZw==?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?UTF-8?B?W2VhaXMjNTU3NzM0XSDQoNC+0YHQutC+0LzQvdCw0LTQt9C+0YAg0LjQvdGE0L7RgNC80LjRgNGD0LXRgi90aGUgUm9zY29tbmFkem9yIGlzIGluZm9ybWluZw==?=", event.IP)
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
