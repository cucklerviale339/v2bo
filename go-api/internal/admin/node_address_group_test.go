package admin

import (
	"reflect"
	"testing"
)

func TestNormalizeNodeAddressGroupSeparatesExplicitIDsAndRanges(t *testing.T) {
	req, err := normalizeNodeAddressGroupSaveRequest(NodeAddressGroupSaveRequest{
		Name: "test",
		Rules: []NodeAddressRuleSaveRequest{
			{
				Host:              "entry.example.com",
				MatchUserIDs:      []string{"10", "20", "10"},
				MatchUserIDRanges: []string{"100-1", "200-300", "1-100"},
			},
		},
	})
	if err != nil {
		t.Fatalf("normalize request: %v", err)
	}
	rule := req.Rules[0]
	if want := []string{"10", "20"}; !reflect.DeepEqual(rule.MatchUserIDs, want) {
		t.Fatalf("explicit IDs = %#v, want %#v", rule.MatchUserIDs, want)
	}
	if want := []string{"1-100", "200-300"}; !reflect.DeepEqual(rule.MatchUserIDRanges, want) {
		t.Fatalf("ID ranges = %#v, want %#v", rule.MatchUserIDRanges, want)
	}
}

func TestNormalizeNodeAddressGroupRejectsRangeInExplicitIDs(t *testing.T) {
	_, err := normalizeNodeAddressGroupSaveRequest(NodeAddressGroupSaveRequest{
		Name: "test",
		Rules: []NodeAddressRuleSaveRequest{
			{Host: "entry.example.com", MatchUserIDs: []string{"1-100"}},
		},
	})
	if err == nil {
		t.Fatal("expected explicit user ID validation error")
	}
}

func TestNormalizeNodeAddressGroupRequiresIDCondition(t *testing.T) {
	_, err := normalizeNodeAddressGroupSaveRequest(NodeAddressGroupSaveRequest{
		Name:  "test",
		Rules: []NodeAddressRuleSaveRequest{{Host: "entry.example.com"}},
	})
	if err == nil {
		t.Fatal("expected missing condition error")
	}
}

func TestNormalizeNodeAddressGroupValidatesExtraNodes(t *testing.T) {
	const extra = "trojan://secret@extra.example.com:443#Extra"
	req, err := normalizeNodeAddressGroupSaveRequest(NodeAddressGroupSaveRequest{
		Name: "test",
		Rules: []NodeAddressRuleSaveRequest{{
			Host:               "entry.example.com",
			MatchUserIDs:       []string{"10"},
			ExtraNodes:         []string{"  " + extra + "  "},
			ExtraNodesPosition: "before",
		}},
	})
	if err != nil {
		t.Fatalf("normalize request: %v", err)
	}
	rule := req.Rules[0]
	if !reflect.DeepEqual(rule.ExtraNodes, []string{extra}) {
		t.Fatalf("extra nodes = %#v", rule.ExtraNodes)
	}
	if rule.ExtraNodesPosition != "before" {
		t.Fatalf("extra node position = %q", rule.ExtraNodesPosition)
	}

	_, err = normalizeNodeAddressGroupSaveRequest(NodeAddressGroupSaveRequest{
		Name: "test",
		Rules: []NodeAddressRuleSaveRequest{{
			Host:         "entry.example.com",
			MatchUserIDs: []string{"10"},
			ExtraNodes:   []string{"not-a-node"},
		}},
	})
	if err == nil {
		t.Fatal("expected invalid extra node to be rejected")
	}
}

func TestNormalizeNodeAddressGroupAllowsExtraNodesWithoutManagedHost(t *testing.T) {
	const extra = "trojan://secret@extra.example.com:443#Extra"
	req, err := normalizeNodeAddressGroupSaveRequest(NodeAddressGroupSaveRequest{
		Name: "test",
		Rules: []NodeAddressRuleSaveRequest{{
			MatchUserIDs: []string{"10"},
			ExtraNodes:   []string{extra},
		}},
	})
	if err != nil {
		t.Fatalf("extra-only rule should be accepted: %v", err)
	}
	if req.Rules[0].Host != "" || !reflect.DeepEqual(req.Rules[0].ExtraNodes, []string{extra}) {
		t.Fatalf("unexpected normalized extra-only rule: %#v", req.Rules[0])
	}

	_, err = normalizeNodeAddressGroupSaveRequest(NodeAddressGroupSaveRequest{
		Name: "test",
		Rules: []NodeAddressRuleSaveRequest{{
			MatchUserIDs: []string{"10"},
		}},
	})
	if err == nil {
		t.Fatal("rule without managed host or extra nodes should be rejected")
	}
}
