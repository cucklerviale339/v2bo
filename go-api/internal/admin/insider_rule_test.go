package admin

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestNormalizeInsiderRuleRejectsInvalidFields(t *testing.T) {
	enabled := int64(2)
	tests := []struct {
		name string
		req  InsiderRuleSaveRequest
	}{
		{name: "empty name", req: InsiderRuleSaveRequest{MatchUserIDs: []string{"1"}, Host: "node.example.com"}},
		{name: "long name", req: InsiderRuleSaveRequest{Name: strings.Repeat("名", 256), MatchUserIDs: []string{"1"}, Host: "node.example.com"}},
		{name: "long host", req: InsiderRuleSaveRequest{Name: "rule", MatchUserIDs: []string{"1"}, Host: strings.Repeat("a", 256)}},
		{name: "conditional host", req: InsiderRuleSaveRequest{Name: "rule", MatchUserIDs: []string{"1"}, Host: "a.example.com(1-2)"}},
		{name: "invalid enabled", req: InsiderRuleSaveRequest{Name: "rule", MatchUserIDs: []string{"1"}, Host: "node.example.com", Enabled: &enabled}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := normalizeInsiderRuleSaveRequest(test.req); !errors.Is(err, ErrInvalidInsiderRule) {
				t.Fatalf("expected invalid insider rule, got %v", err)
			}
		})
	}
}

func TestNormalizeInsiderRuleLimitsAndClearsObsoleteFields(t *testing.T) {
	ids := make([]string, maxInsiderRuleMatches+1)
	for index := range ids {
		ids[index] = strconv.Itoa(index + 1)
	}
	if _, err := normalizeInsiderRuleSaveRequest(InsiderRuleSaveRequest{Name: "rule", MatchUserIDs: ids, Host: "node.example.com"}); !errors.Is(err, ErrInvalidInsiderRule) {
		t.Fatalf("expected match limit error, got %v", err)
	}

	sortValue := int64(-100)
	normalized, err := normalizeInsiderRuleSaveRequest(InsiderRuleSaveRequest{
		Name: " rule ", MatchUserIDs: []string{"2", "2"}, Host: " node.example.com ",
		Members: []InsiderRuleMember{{ServerType: "vmess", ServerID: 9}}, Sort: &sortValue,
	})
	if err != nil {
		t.Fatalf("normalize valid rule: %v", err)
	}
	if normalized.Name != "rule" || normalized.Host != "node.example.com" || len(normalized.MatchUserIDs) != 1 {
		t.Fatalf("unexpected normalized rule: %#v", normalized)
	}
	if len(normalized.Members) != 0 || normalized.Sort != nil {
		t.Fatalf("obsolete fields were not cleared: %#v", normalized)
	}
}
