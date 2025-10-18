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
	if event.IP != "Fwd: [SpamCop (http://vko6jh5zoi0qfrwdk.literacystatistics.co.uk/bx.ddp?P19l6h20fh6FqDTfcQmw419nKg8wQYjLrSvlBtWjw5z8zR53JdlJgsD0p4LMm0SnLmQvSKw6tVLPCNgk3X8cKK20Ng7Xw9fxf3vlX7gXH3zNsY4KvndH1zyfmfYR3c4WcRSzFM4vTw0dlT8b4YW3ksy91xwnr6gDDwRshJbMN08NTFVrbsqgPX09jvBT9xywDZsWK4J2PZl4GrycQnrxYzzDs3mCtrwzDy9sSwWJDVQG2yXby87VK8LbwtCmRsTKddfYDYszNgjHQvXQfT3z6S2VD0xHjRfN67bdqtDxLgCFWvnk83LSzSYMcY5JLCb6k0jXTcmMYHrDBNCvHKB60fFwrX8rN3bKl5PnYHD2G3DGDWmVwzyr8LJZJyzgCFwC6YcHyc9fSz4LQz3Q6xzcd7YPYrcTdlhVcRtqJ8HKK70xP4ncSnrc7LXN9fYKgZCMgXvQQk09Cxf1GHzX0YTdGPGv3ZSnMHft7J7c84jlpSh47fSnDYz2jsp0d1sz7zJKmvnpLPfMcC8kBTqmkVdwVtJF8B3L496kZZbFzJpDjpM5BSL0HZkCcbfHjD03Cfcgj5MRs1V4Vb3QM3W0BLFYRX13rC1WtP6FXNMrmqbVJvqMYw9SWRP1SRc08BST4R3PjL97ywMNdjzcz2T2frxXZxQyVgKPmQ7Fv1k3pCHDCJdw4P29n9ZqzQmhC931fPwrCCjxyVzzyvrfqgskRfPvJYVtX4dZ4PkCKlmbnQyYs0wSM3L235cvGWf34ZNQb6NKwjqqyShqMqghBZQV6NTkPCqWNR36kFWKrfjsnsHTmhdGRY90jLblLHVbc01rdXXPmxl7TXJCtxk5wtyV2HK84qz3DxLVngQC6Mtks7FfdM2pKsKj8nww8KGm8mLYMZJfcz9xnKWhCr3J64gYnm Nt NZGkj7wHbcpJ8GhN" {
		t.Errorf("Event 0: Expected IP %q, got %q", "Fwd: [SpamCop (http://vko6jh5zoi0qfrwdk.literacystatistics.co.uk/bx.ddp?P19l6h20fh6FqDTfcQmw419nKg8wQYjLrSvlBtWjw5z8zR53JdlJgsD0p4LMm0SnLmQvSKw6tVLPCNgk3X8cKK20Ng7Xw9fxf3vlX7gXH3zNsY4KvndH1zyfmfYR3c4WcRSzFM4vTw0dlT8b4YW3ksy91xwnr6gDDwRshJbMN08NTFVrbsqgPX09jvBT9xywDZsWK4J2PZl4GrycQnrxYzzDs3mCtrwzDy9sSwWJDVQG2yXby87VK8LbwtCmRsTKddfYDYszNgjHQvXQfT3z6S2VD0xHjRfN67bdqtDxLgCFWvnk83LSzSYMcY5JLCb6k0jXTcmMYHrDBNCvHKB60fFwrX8rN3bKl5PnYHD2G3DGDWmVwzyr8LJZJyzgCFwC6YcHyc9fSz4LQz3Q6xzcd7YPYrcTdlhVcRtqJ8HKK70xP4ncSnrc7LXN9fYKgZCMgXvQQk09Cxf1GHzX0YTdGPGv3ZSnMHft7J7c84jlpSh47fSnDYz2jsp0d1sz7zJKmvnpLPfMcC8kBTqmkVdwVtJF8B3L496kZZbFzJpDjpM5BSL0HZkCcbfHjD03Cfcgj5MRs1V4Vb3QM3W0BLFYRX13rC1WtP6FXNMrmqbVJvqMYw9SWRP1SRc08BST4R3PjL97ywMNdjzcz2T2frxXZxQyVgKPmQ7Fv1k3pCHDCJdw4P29n9ZqzQmhC931fPwrCCjxyVzzyvrfqgskRfPvJYVtX4dZ4PkCKlmbnQyYs0wSM3L235cvGWf34ZNQb6NKwjqqyShqMqghBZQV6NTkPCqWNR36kFWKrfjsnsHTmhdGRY90jLblLHVbc01rdXXPmxl7TXJCtxk5wtyV2HK84qz3DxLVngQC6Mtks7FfdM2pKsKj8nww8KGm8mLYMZJfcz9xnKWhCr3J64gYnm Nt NZGkj7wHbcpJ8GhN", event.IP)
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
