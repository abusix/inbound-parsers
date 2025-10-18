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
	if event.IP != "=?utf-8?Q?Important=20Notice:=20Harmful=20Cyber=20Operation=20on=20Your=20Network=20=E2=80=93=20Tech=20Support=20Fraud=20/=20Incident=20ID:=2066221955=20/=20IP=20Address:=2080.211.34.145=20/=20ASN:=20ARUBA-ASN=20=2C=20IT?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?utf-8?Q?Important=20Notice:=20Harmful=20Cyber=20Operation=20on=20Your=20Network=20=E2=80=93=20Tech=20Support=20Fraud=20/=20Incident=20ID:=2066221955=20/=20IP=20Address:=2080.211.34.145=20/=20ASN:=20ARUBA-ASN=20=2C=20IT?=", event.IP)
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
