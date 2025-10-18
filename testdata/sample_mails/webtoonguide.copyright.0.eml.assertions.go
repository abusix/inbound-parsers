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
	if event.IP != "=?UTF-8?q?Copyright_Infringement_&_DMCA_Violations_-_Domain:_mangadora.co?= =?UTF-8?q?m,__8_contents_including_content:_\"=EC=82=AC=EC=83=81=EC=B5=9C?= =?UTF-8?q?=EA=B0=95\"?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?UTF-8?q?Copyright_Infringement_&_DMCA_Violations_-_Domain:_mangadora.co?= =?UTF-8?q?m,__8_contents_including_content:_\"=EC=82=AC=EC=83=81=EC=B5=9C?= =?UTF-8?q?=EA=B0=95\"?=", event.IP)
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
