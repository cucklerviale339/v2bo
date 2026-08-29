package user

import (
	"testing"

	"forest/go-api/internal/subscribelink"
)

func TestNodeAddressRuleMatchesRequiresCondition(t *testing.T) {
	user := serverFetchUser{
		ID:      10,
		GroupID: 20,
		PlanID:  30,
	}

	if (nodeAddressRule{Host: "default.example.com"}).matches(user) {
		t.Fatal("rule without any condition must not match")
	}

	if !(nodeAddressRule{Host: "user.example.com", MatchUserIDs: []string{"10"}}).matches(user) {
		t.Fatal("rule with a matching condition should match")
	}

	if (nodeAddressRule{Host: "other.example.com", MatchUserIDs: []string{"11"}}).matches(user) {
		t.Fatal("rule with a non-matching condition must not match")
	}

	if !(nodeAddressRule{Host: "range.example.com", MatchUserIDRanges: []string{"1-20"}}).matches(user) {
		t.Fatal("rule with a matching user ID range should match")
	}
}

func TestNodeAddressSelectorPrefersExplicitUserIDOverRange(t *testing.T) {
	selector := &nodeAddressSelector{
		bindings: map[string]int64{"vmess-7": 3},
		rules: map[int64][]nodeAddressRule{
			3: {
				{ID: 1, Host: "range.example.com", MatchUserIDRanges: []string{"1-100"}},
				{ID: 2, Host: "explicit.example.com", MatchUserIDs: []string{"10"}, ExtraNodes: []string{"trojan://secret@extra.example.com:443#Extra"}},
			},
		},
	}

	host, ok := selector.Resolve("vmess", 7, serverFetchUser{ID: 10})
	if !ok || host != "explicit.example.com" {
		t.Fatalf("explicit user ID should win, got host=%q ok=%v", host, ok)
	}
	matchedRule, ok := selector.ResolveRule("vmess", 7, serverFetchUser{ID: 10})
	if !ok || matchedRule.ID != 2 || len(matchedRule.ExtraNodes) != 1 {
		t.Fatalf("explicit rule details were not preserved: %#v, ok=%v", matchedRule, ok)
	}

	host, ok = selector.Resolve("vmess", 7, serverFetchUser{ID: 20})
	if !ok || host != "range.example.com" {
		t.Fatalf("range should be used as fallback, got host=%q ok=%v", host, ok)
	}

	if host, ok = selector.Resolve("vmess", 7, serverFetchUser{ID: 101}); ok || host != "" {
		t.Fatalf("unmatched user should fall back to the original node host, got host=%q ok=%v", host, ok)
	}
}

func TestAppendNodeAddressExtraNodesPreservesConfiguredModeAndCredential(t *testing.T) {
	beforeURI := "trojan://before-secret@before.example.com:443#Before"
	replaceURI := "trojan://replace-secret@replace.example.com:443#Replace"
	servers := []map[string]any{{"id": int64(7), "name": "Managed", "sort": int64(10)}}
	rules := []nodeAddressRule{
		{ID: 2, ExtraNodes: []string{beforeURI}, ExtraNodesPosition: subscribelink.PositionBefore},
		{ID: 3, ExtraNodes: []string{replaceURI}, ExtraNodesPosition: subscribelink.PositionReplace},
	}

	result := appendNodeAddressExtraNodes(servers, rules)
	if len(result) != 3 {
		t.Fatalf("extra node result = %#v", result)
	}
	if got := subscribelink.RawURI(result[0]); got != beforeURI {
		t.Fatalf("before URI = %q", got)
	}
	if result[1]["name"] != "Managed" {
		t.Fatalf("managed node moved unexpectedly: %#v", result)
	}
	if got := subscribelink.RawURI(result[2]); got != replaceURI {
		t.Fatalf("replacement URI = %q", got)
	}
	if got := subscribelink.Credential("subscriber-uuid", result[0]); got != "before-secret" {
		t.Fatalf("extra credential = %q", got)
	}
}

func TestApplyNodeAddressSelectionKeepsManagedNodeInBeforeMode(t *testing.T) {
	selector := &nodeAddressSelector{
		bindings: map[string]int64{"vmess-7": 3},
		rules: map[int64][]nodeAddressRule{3: {{
			ID: 9, MatchUserIDs: []string{"10"},
			ExtraNodes:         []string{"trojan://secret@extra.example.com:443#Extra"},
			ExtraNodesPosition: subscribelink.PositionBefore,
		}}},
	}
	managed := map[string]any{"id": int64(7), "type": "vmess", "host": "original.example.com"}

	extraRule, keepManaged := applyNodeAddressSelection(managed, selector, serverFetchUser{ID: 10}, "", 0)
	if !keepManaged || extraRule == nil {
		t.Fatalf("before mode must retain managed node: keep=%v rule=%#v", keepManaged, extraRule)
	}
}

func TestInsiderSelectionHasPriorityBehavior(t *testing.T) {
	selector := &insiderSelector{rules: []insiderRule{{
		nodeAddressRule: nodeAddressRule{ID: 5, Host: "insider.example.com", MatchUserIDs: []string{"10"}},
	}}}
	managed := map[string]any{"id": int64(7), "type": "vmess", "host": "original.example.com"}

	extra, keep, matched := applyInsiderSelection(managed, selector, 10)
	if !matched || !keep || extra != nil {
		t.Fatalf("unexpected insider result: matched=%v keep=%v extra=%#v", matched, keep, extra)
	}
	if host, ok := managed["host"].(AddressGroupHost); !ok || host != "insider.example.com" {
		t.Fatalf("insider host was not applied: %#v", managed["host"])
	}
}

func TestInsiderSelectionCanReplaceManagedNode(t *testing.T) {
	selector := &insiderSelector{rules: []insiderRule{{
		nodeAddressRule: nodeAddressRule{ID: 5, MatchUserIDRanges: []string{"1-20"}, ExtraNodes: []string{"trojan://secret@extra.example.com:443#Extra"}, ExtraNodesPosition: subscribelink.PositionReplace},
	}}}
	managed := map[string]any{"id": int64(7), "type": "vmess", "host": "original.example.com"}

	extra, keep, matched := applyInsiderSelection(managed, selector, 10)
	if !matched || keep || extra == nil || extra.ID != 5 {
		t.Fatalf("replace mode did not replace managed node: matched=%v keep=%v extra=%#v", matched, keep, extra)
	}
}

func TestApplyNodeAddressSelectionUsesExtraNodesInsteadOfManagedNode(t *testing.T) {
	const extraURI = "trojan://extra-secret@extra.example.com:443#Extra"
	selector := &nodeAddressSelector{
		bindings: map[string]int64{"vmess-7": 3},
		rules: map[int64][]nodeAddressRule{
			3: {{
				ID:           9,
				MatchUserIDs: []string{"10"},
				ExtraNodes:   []string{extraURI},
			}},
		},
	}
	managed := map[string]any{
		"id":   int64(7),
		"type": "vmess",
		"name": "Managed",
		"host": "original.example.com",
		"sort": int64(10),
	}

	extraRule, keepManaged := applyNodeAddressSelection(managed, selector, serverFetchUser{ID: 10}, "", 0)
	if keepManaged || extraRule == nil || extraRule.ID != 9 {
		t.Fatalf("extra rule must replace managed node: keep=%v rule=%#v", keepManaged, extraRule)
	}
	result := appendNodeAddressExtraNodes(nil, []nodeAddressRule{*extraRule})
	if len(result) != 1 || subscribelink.RawURI(result[0]) != extraURI {
		t.Fatalf("expected only the configured extra node, got %#v", result)
	}
}

func TestApplyNodeAddressSelectionFallsBackToLegacyHostConditionsWhenRuleDoesNotMatch(t *testing.T) {
	selector := &nodeAddressSelector{
		bindings: map[string]int64{"vmess-7": 3},
		rules: map[int64][]nodeAddressRule{
			3: {{
				ID:           9,
				Host:         "selected.example.com",
				MatchUserIDs: []string{"99"},
			}},
		},
	}
	managed := map[string]any{
		"id":   int64(7),
		"type": "vmess",
		"host": "legacy.example.com(1-20),default.example.com",
	}

	extraRule, keepManaged := applyNodeAddressSelection(managed, selector, serverFetchUser{ID: 10}, "", 0)
	if !keepManaged || extraRule != nil {
		t.Fatalf("unmatched address rule should use legacy parsing: keep=%v rule=%#v", keepManaged, extraRule)
	}
	if managed["host"] != "legacy.example.com" {
		t.Fatalf("legacy host condition was not applied: %#v", managed["host"])
	}
}

func TestApplyNodeAddressSelectionUsesManagedNodeWhenExtraNodesAreEmpty(t *testing.T) {
	selector := &nodeAddressSelector{
		bindings: map[string]int64{"vmess-7": 3},
		rules: map[int64][]nodeAddressRule{
			3: {{
				ID:           9,
				Host:         "selected.example.com",
				MatchUserIDs: []string{"10"},
			}},
		},
	}
	managed := map[string]any{
		"id":   int64(7),
		"type": "vmess",
		"host": "original.example.com",
	}

	extraRule, keepManaged := applyNodeAddressSelection(managed, selector, serverFetchUser{ID: 10}, "", 0)
	if !keepManaged || extraRule != nil {
		t.Fatalf("managed node should remain when extras are empty: keep=%v rule=%#v", keepManaged, extraRule)
	}
	if host, ok := managed["host"].(AddressGroupHost); !ok || host != "selected.example.com" {
		t.Fatalf("managed node did not use the selected address: %#v", managed["host"])
	}
}
