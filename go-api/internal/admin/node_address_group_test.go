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
