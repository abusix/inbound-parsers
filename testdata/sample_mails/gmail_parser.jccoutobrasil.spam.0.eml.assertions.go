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
	if event.IP != "=?UTF-8?Q?Reporting_suspicious_e=2Dmail_=28SPAM_=2F_SCAM_=2F_SPOOFING_?= =?UTF-8?Q?=2F_PHISHING=29=3A_POR_FAVOR=2C_VOC=C3=8A_RECEBEU_MINHA_PRIMEIRA_MENSAGE?= =?UTF-8?Q?M_PARA_VOC=C3=8A=3F_VOLTE_PARA_MIM=2E?=" {
		t.Errorf("Event 0: Expected IP %q, got %q", "=?UTF-8?Q?Reporting_suspicious_e=2Dmail_=28SPAM_=2F_SCAM_=2F_SPOOFING_?= =?UTF-8?Q?=2F_PHISHING=29=3A_POR_FAVOR=2C_VOC=C3=8A_RECEBEU_MINHA_PRIMEIRA_MENSAGE?= =?UTF-8?Q?M_PARA_VOC=C3=8A=3F_VOLTE_PARA_MIM=2E?=", event.IP)
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
