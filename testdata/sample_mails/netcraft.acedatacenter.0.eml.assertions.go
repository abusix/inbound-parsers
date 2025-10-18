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
	if event.IP != "Fwd: Issue 27142006: Package scam URL at hxxp://hhxos8ui06gf2hpbr93.literacystatistics.co[.]uk/sz.fi?GJmRh5fLMB97Kf3fCChZKtmyKx9ydJWDlDRth5G4HRLB2W0fyR5Yq4sWkB1lVp5tHWtk4nw7WV7mhdK0V9NM2QhR0HzZYzSyCq0vzH34fVLtgD8X4nLcqDMXWlGKrC9BZsS3CbzCMWpQqzzyNcRbkNVx8B4fQ8wP1vTYCMf0ZP2N0Td67mK14chhjdZ6H4DCkjMwvxKpHT0Tk6xj3Z4mV7tw2VySZTBp0L0lYFf4RlGXmlHt73ry0PPzDvkXMLhgjyWyZK2VGCmvGWBj4VjctlchFcRSLbfnPNTH22bbLgh4G5fLt5FF68KtRb8xrhr4hcfHz5G8lKCS01Y6nwXbjR23RkSZT8ZTbRg3QHBk1sJ6BJLG088sHZHnnYsYsXwBVXzK9Wdc9Hnl0jSRGw9vpxtwQdpgtXylFwxNVFsPVx5KQMdqRD2RXDQGMmp1RZNC9km1QpD7JgpVwdPxdXkrT41T3VrRX0s65LNCRJlGQ7qh8J6BVCNcMdtbw5GRQ28svDY6f7pStdchhkJdk81mG4nPhNg0zGXyjyBKqdqkf2s0kZll1zzftDMz3W89kp6GYFLv9czxwhC3yvpC94DRl2r2xmmw5w4J3yDPc6Y7p2N2v8NKlpNpDQvS5NQCVJD4Rgpk0BMw3dT2xs5mfXjtjmshkXjCNmQJNNfrsvYwL5VXxhJFljXdb6fLcL7vDJ3d9y0Ltw7knvrkDrvnTnvRqc9mzz8T3NCpPfhV330g4lFtxYXm8gpxRlrxDtCd8M4hcS8z9j15c8FlRhb1DgyNlzGT6hhrL61LJvPkNlnh1VcLJtNmPysh4F3sFJG1pXsWm0ld7zQtTS5RMnmmy0gMZxzl4H24Wv2QGDvw8VRYSZNpFJC6D FLgs3c qV gP76k44Nzg87s" {
		t.Errorf("Event 0: Expected IP %q, got %q", "Fwd: Issue 27142006: Package scam URL at hxxp://hhxos8ui06gf2hpbr93.literacystatistics.co[.]uk/sz.fi?GJmRh5fLMB97Kf3fCChZKtmyKx9ydJWDlDRth5G4HRLB2W0fyR5Yq4sWkB1lVp5tHWtk4nw7WV7mhdK0V9NM2QhR0HzZYzSyCq0vzH34fVLtgD8X4nLcqDMXWlGKrC9BZsS3CbzCMWpQqzzyNcRbkNVx8B4fQ8wP1vTYCMf0ZP2N0Td67mK14chhjdZ6H4DCkjMwvxKpHT0Tk6xj3Z4mV7tw2VySZTBp0L0lYFf4RlGXmlHt73ry0PPzDvkXMLhgjyWyZK2VGCmvGWBj4VjctlchFcRSLbfnPNTH22bbLgh4G5fLt5FF68KtRb8xrhr4hcfHz5G8lKCS01Y6nwXbjR23RkSZT8ZTbRg3QHBk1sJ6BJLG088sHZHnnYsYsXwBVXzK9Wdc9Hnl0jSRGw9vpxtwQdpgtXylFwxNVFsPVx5KQMdqRD2RXDQGMmp1RZNC9km1QpD7JgpVwdPxdXkrT41T3VrRX0s65LNCRJlGQ7qh8J6BVCNcMdtbw5GRQ28svDY6f7pStdchhkJdk81mG4nPhNg0zGXyjyBKqdqkf2s0kZll1zzftDMz3W89kp6GYFLv9czxwhC3yvpC94DRl2r2xmmw5w4J3yDPc6Y7p2N2v8NKlpNpDQvS5NQCVJD4Rgpk0BMw3dT2xs5mfXjtjmshkXjCNmQJNNfrsvYwL5VXxhJFljXdb6fLcL7vDJ3d9y0Ltw7knvrkDrvnTnvRqc9mzz8T3NCpPfhV330g4lFtxYXm8gpxRlrxDtCd8M4hcS8z9j15c8FlRhb1DgyNlzGT6hhrL61LJvPkNlnh1VcLJtNmPysh4F3sFJG1pXsWm0ld7zQtTS5RMnmmy0gMZxzl4H24Wv2QGDvw8VRYSZNpFJC6D FLgs3c qV gP76k44Nzg87s", event.IP)
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
