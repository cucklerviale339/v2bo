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
}
