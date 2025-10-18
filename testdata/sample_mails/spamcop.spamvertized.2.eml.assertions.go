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
	if event.IP != "[SpamCop (https://ever3trk.com/click.ash?AFIDC0415&amp;CIDA3801&amp;ADID!98515&amp;SIDt633&amp;AffiliateReferenceID�d7506e-9b9d-11e9-a7bc-df5d7mpaign_id\x1228&amp;p_idX4&amp;id=XNSX.ts5475%7C%7Cinternational%7C%7Cgeneral%3A%3A1561944850.81%7C%7C161229585%7C%7C0%7C%7C-r74633-t488&amp;impidSe9ed30-9ba0-11e9-8a7e-cae258990218&amp;tovh2190) id:6971183695]Sign up today and enjoy a fabulous experience" {
		t.Errorf("Event 0: Expected IP %q, got %q", "[SpamCop (https://ever3trk.com/click.ash?AFIDC0415&amp;CIDA3801&amp;ADID!98515&amp;SIDt633&amp;AffiliateReferenceID�d7506e-9b9d-11e9-a7bc-df5d7mpaign_id\x1228&amp;p_idX4&amp;id=XNSX.ts5475%7C%7Cinternational%7C%7Cgeneral%3A%3A1561944850.81%7C%7C161229585%7C%7C0%7C%7C-r74633-t488&amp;impidSe9ed30-9ba0-11e9-8a7e-cae258990218&amp;tovh2190) id:6971183695]Sign up today and enjoy a fabulous experience", event.IP)
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
