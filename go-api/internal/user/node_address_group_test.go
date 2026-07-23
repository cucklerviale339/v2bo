package user

import "testing"

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
				{Host: "range.example.com", MatchUserIDRanges: []string{"1-100"}},
				{Host: "explicit.example.com", MatchUserIDs: []string{"10"}},
			},
		},
	}

	host, ok := selector.Resolve("vmess", 7, serverFetchUser{ID: 10})
	if !ok || host != "explicit.example.com" {
		t.Fatalf("explicit user ID should win, got host=%q ok=%v", host, ok)
	}

	host, ok = selector.Resolve("vmess", 7, serverFetchUser{ID: 20})
	if !ok || host != "range.example.com" {
		t.Fatalf("range should be used as fallback, got host=%q ok=%v", host, ok)
	}

	if host, ok = selector.Resolve("vmess", 7, serverFetchUser{ID: 101}); ok || host != "" {
		t.Fatalf("unmatched user should fall back to the original node host, got host=%q ok=%v", host, ok)
	}
}
