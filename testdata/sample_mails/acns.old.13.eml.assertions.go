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
	if event.IP != "95.222.9.239" {
		t.Errorf("Event 0: Expected IP %q, got %q", "95.222.9.239", event.IP)
	}
	if event.URL != "ed2k://|file|1000%E7%A7%8D%E6%AD%BB%E6%B3%95%2E1000%2EWays%2ETo%2EDie%2ES04E01%2EChi%5FEng%2EHR%2DHDTV%2EAC3%2E1024X576%2Ex264%2DYYeTs%E4%BA%BA%E4%BA%BA%E5%BD%B1%E8%A7%86%2Emkv|261297474|0077A0135F5A042FFDEB76D15FFCDD29|/" {
		t.Errorf("Event 0: Expected URL %q, got %q", "ed2k://|file|1000%E7%A7%8D%E6%AD%BB%E6%B3%95%2E1000%2EWays%2ETo%2EDie%2ES04E01%2EChi%5FEng%2EHR%2DHDTV%2EAC3%2E1024X576%2Ex264%2DYYeTs%E4%BA%BA%E4%BA%BA%E5%BD%B1%E8%A7%86%2Emkv|261297474|0077A0135F5A042FFDEB76D15FFCDD29|/", event.URL)
	}
	if event.Port != 49679 {
		t.Errorf("Event 0: Expected Port %d, got %d", 49679, event.Port)
	}
	if event.Parser != "acns" {
		t.Errorf("Event 0: Expected Parser %q, got %q", "acns", event.Parser)
	}
	if len(event.EventTypes) == 0 {
		t.Errorf("Event 0: Expected event type, got none")
	} else {
		eventType := fmt.Sprintf("%T", event.EventTypes[0])
		if !strings.Contains(eventType, "Copyright") {
			t.Errorf("Event 0: Expected event type containing %q, got %s", "Copyright", eventType)
		}
	}
	if len(event.EventDetails) != 6 {
		t.Errorf("Event 0: Expected 6 event details, got %d", len(event.EventDetails))
	}

}
