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
	if event.IP != "=?UTF-8?Q?[External_Sender]_Violazione_dei_diritti_di_p?= =?UTF-8?Q?ropriet=C3=A0_intellettuale_di_MONDADORI_MEDIA_S.?= =?UTF-8?Q?P.A._attraverso_il_sito_web_www.chisettimanal?= =?UTF-8?Q?e.it_(Ns._Rif.:_D0030947_Mondadori_Media_S.p.?= =?UTF-8?Q?A._v._TBD_-_chisettimanale.it)?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?UTF-8?Q?[External_Sender]_Violazione_dei_diritti_di_p?= =?UTF-8?Q?ropriet=C3=A0_intellettuale_di_MONDADORI_MEDIA_S.?= =?UTF-8?Q?P.A._attraverso_il_sito_web_www.chisettimanal?= =?UTF-8?Q?e.it_(Ns._Rif.:_D0030947_Mondadori_Media_S.p.?= =?UTF-8?Q?A._v._TBD_-_chisettimanale.it)?=", event.IP)
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
