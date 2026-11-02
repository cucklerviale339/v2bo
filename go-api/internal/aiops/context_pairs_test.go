package aiops

import "testing"

func assertContextToolPairs(t *testing.T, messages []providerMessage) {
	t.Helper()
	pending := map[string]bool{}
	for _, message := range messages {
		if message.Role != "tool" && len(pending) != 0 {
			t.Fatalf("tool results interrupted by %s: %v", message.Role, pending)
		}
		if message.Role == "tool" {
			if !pending[message.ToolCallID] {
				t.Fatalf("orphan or duplicate tool result %s", message.ToolCallID)
			}
			delete(pending, message.ToolCallID)
		}
		for _, call := range message.ToolCalls {
			if pending[call.ID] {
				t.Fatalf("duplicate pending call %s", call.ID)
			}
			pending[call.ID] = true
		}
	}
	if len(pending) != 0 {
		t.Fatalf("missing tool results: %v", pending)
	}
}
