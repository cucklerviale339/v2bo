package user

import (
	"context"
	"testing"

	"forest/go-api/internal/config"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestLoadInsiderSelectorIgnoresObsoleteMembersColumn(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("create sql mock: %v", err)
	}
	defer db.Close()

	service := NewDBService(config.Config{}, db)
	service.nodeAddressEnsureOnce.Do(func() {})
	mock.ExpectQuery(`SELECT id, match_user_ids, match_user_id_ranges, host, extra_nodes, extra_nodes_position FROM v2_insider_rule WHERE enabled=1 ORDER BY id ASC`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "match_user_ids", "match_user_id_ranges", "host", "extra_nodes", "extra_nodes_position"}).
			AddRow(int64(7), `["10"]`, `[]`, "inside.example.com", `[]`, "replace"))

	selector, err := service.loadInsiderSelector(context.Background())
	if err != nil {
		t.Fatalf("load selector: %v", err)
	}
	rule, matched := selector.Resolve(10)
	if !matched || rule.ID != 7 || rule.Host != "inside.example.com" {
		t.Fatalf("unexpected selection: matched=%v rule=%#v", matched, rule)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestInsiderSelectorPrefersExplicitUserOverRange(t *testing.T) {
	selector := &insiderSelector{rules: []insiderRule{
		{nodeAddressRule: nodeAddressRule{ID: 1, Host: "range.example.com", MatchUserIDRanges: []string{"1-100"}}},
		{nodeAddressRule: nodeAddressRule{ID: 2, Host: "exact.example.com", MatchUserIDs: []string{"10"}}},
	}}
	rule, matched := selector.Resolve(10)
	if !matched || rule.ID != 2 {
		t.Fatalf("explicit rule should win: matched=%v rule=%#v", matched, rule)
	}
}
