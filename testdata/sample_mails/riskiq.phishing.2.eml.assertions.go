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
	if event.IP != "PLEASE TAKE NOTICE - Phishing Materials Utilising Your Network Resources / Incident ID: 69678178 / IP Address: 172.105.110.43 / ASN: LINODE-AP Linode, LLC, SG" {
		t.Errorf("Event 0: Expected IP %q, got %q", "PLEASE TAKE NOTICE - Phishing Materials Utilising Your Network Resources / Incident ID: 69678178 / IP Address: 172.105.110.43 / ASN: LINODE-AP Linode, LLC, SG", event.IP)
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
