package user

import (
	"context"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"testing"

	"forest/go-api/internal/subscribelink"
	"github.com/DATA-DOG/go-sqlmock"
)

func TestDispatchEntriesPriorityAndDeduplicatedOwnership(t *testing.T) {
	servers := []map[string]any{{"type": "vmess", "id": int64(7), "host": "base.example.com"}}
	addresses := &nodeAddressSelector{bindings: map[string]int64{"vmess-7": 3}, rules: map[int64][]nodeAddressRule{3: {
		{ID: 1, Host: "range.example.com", MatchUserIDRanges: []string{"1-100"}},
		{ID: 2, Host: "exact.example.com", MatchUserIDs: []string{"10,20"}},
		{ID: 3, Host: "shadowed.example.com", MatchUserIDRanges: []string{"1-50"}},
	}}}
	insiders := &insiderSelector{rules: []insiderRule{
		{nodeAddressRule{ID: 1, Host: "inside.example.com", MatchUserIDRanges: []string{"15-25"}}},
		{nodeAddressRule{ID: 2, Host: "EXACT.EXAMPLE.COM.", MatchUserIDs: []string{"18"}}},
	}}
	entries, err := configuredDispatchEntries(context.Background(), servers, addresses, insiders)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][2][]string{
		"base.example.com":   {{}, {"101-9223372036854775807"}},
		"exact.example.com":  {{"10", "18"}, {}},
		"inside.example.com": {{}, {"15-17", "19-25"}},
		"range.example.com":  {{}, {"1-9", "11-14", "26-100"}},
	}
	if len(entries) != len(want) {
		t.Fatalf("entries = %#v", entries)
	}
	for _, entry := range entries {
		scope, ok := want[entry.Host]
		if !ok || !reflect.DeepEqual(entry.UserIDs, scope[0]) || !reflect.DeepEqual(entry.UserIDRanges, scope[1]) {
			t.Errorf("unexpected scope: %#v", entry)
		}
		if entry.Host == "exact.example.com" && len(entry.Sources) != 2 {
			t.Errorf("dedup lost sources: %#v", entry)
		}
	}
}

func TestDispatchEntriesMatchExistingSelectorsAcrossOverlaps(t *testing.T) {
	addresses := &nodeAddressSelector{bindings: map[string]int64{"trojan-1": 1}, rules: map[int64][]nodeAddressRule{1: {
		{ID: 1, Host: "a.example", MatchUserIDRanges: []string{"3-30", "60-40"}},
		{ID: 2, Host: "b.example", MatchUserIDs: []string{"10,45,90"}, MatchUserIDRanges: []string{"1-100"}},
		{ID: 3, Host: "c.example", MatchUserIDs: []string{"10,70"}},
	}}}
	insiders := &insiderSelector{rules: []insiderRule{
		{nodeAddressRule{ID: 1, Host: "i.example", MatchUserIDRanges: []string{"5-15", "40-50"}}},
		{nodeAddressRule{ID: 2, Host: "j.example", MatchUserIDs: []string{"12,80"}}},
	}}
	entries, err := configuredDispatchEntries(context.Background(), []map[string]any{{"type": "trojan", "id": int64(1), "host": "base.example"}}, addresses, insiders)
	if err != nil {
		t.Fatal(err)
	}
	for id := int64(1); id <= 120; id++ {
		want := "base.example"
		if rule, ok := insiders.Resolve(id); ok {
			want = rule.Host
		} else if host, ok := addresses.Resolve("trojan", 1, serverFetchUser{ID: id}); ok {
			want = host
		}
		var got []string
		for _, entry := range entries {
			if nodeAddressExactIDTokensMatch(entry.UserIDs, id) || nodeAddressIDRangeTokensMatch(entry.UserIDRanges, id) {
				got = append(got, entry.Host)
			}
		}
		if !reflect.DeepEqual(got, []string{want}) {
			t.Fatalf("ID %d: %v want %s", id, got, want)
		}
	}
}

func TestDispatchEntriesIgnoreConditionalPredicatesAndExcludeExtraNodes(t *testing.T) {
	servers := []map[string]any{{"type": "vmess", "id": int64(1), "host": "base.example(UClash),other.example(P3-5),base.example"}}
	addresses := &nodeAddressSelector{bindings: map[string]int64{"vmess-1": 1}, rules: map[int64][]nodeAddressRule{1: {
		{ID: 1, Host: "unused.example", MatchUserIDs: []string{"2"}, ExtraNodes: []string{"trojan://secret@extra.example:443"}, ExtraNodesPosition: subscribelink.PositionBefore},
		{ID: 2, Host: "replaced.example", MatchUserIDs: []string{"3"}, ExtraNodes: []string{"trojan://secret@extra.example:443"}, ExtraNodesPosition: subscribelink.PositionReplace},
	}}}
	entries, err := configuredDispatchEntries(context.Background(), servers, addresses, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries=%#v", entries)
	}
	for _, entry := range entries {
		if entry.Host != "base.example" && entry.Host != "other.example" {
			t.Fatalf("extra/replaced host included: %#v", entry)
		}
		if !reflect.DeepEqual(entry.UserIDRanges, []string{"1-2", "4-9223372036854775807"}) {
			t.Fatalf("scope=%#v", entry)
		}
	}
}

func TestDispatchSpansMaxIDAndHoles(t *testing.T) {
	got := subtractDispatchSpans([]dispatchSpan{{1, math.MaxInt64}}, []dispatchSpan{{1, 1}, {3, 4}, {math.MaxInt64, math.MaxInt64}})
	if want := []dispatchSpan{{2, 2}, {5, math.MaxInt64 - 1}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("%v want %v", got, want)
	}
	got = mergeDispatchSpans([]dispatchSpan{{math.MaxInt64, math.MaxInt64}, {1, 2}, {3, math.MaxInt64 - 1}})
	if !reflect.DeepEqual(got, []dispatchSpan{{1, math.MaxInt64}}) {
		t.Fatal(got)
	}
}

func TestDispatchCatalogDoesNotReadAccountsOrNodePermissions(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &DBService{db: db}
	s.nodeAddressEnsureOnce.Do(func() {})
	mock.ExpectQuery(`SELECT r.id, r.group_id`).WillReturnRows(sqlmock.NewRows([]string{"id", "group_id", "host", "ids", "ranges", "extra", "position"}))
	mock.ExpectQuery(`SELECT b.server_type`).WillReturnRows(sqlmock.NewRows([]string{"type", "id", "group_id"}))
	mock.ExpectQuery(`SELECT id, match_user_ids`).WillReturnRows(sqlmock.NewRows([]string{"id", "ids", "ranges", "host", "extra", "position"}))
	for _, table := range serverFetchTables {
		mock.ExpectQuery(regexp.QuoteMeta(fmt.Sprintf(`SELECT id, host FROM %s WHERE "show" = 1 ORDER BY id ASC`, table.table))).WillReturnRows(sqlmock.NewRows([]string{"id", "host"}).AddRow(int64(1), "shared.example"))
	}
	mock.ExpectQuery(`SELECT m.group_id,m.root_id`).WithArgs(int64(0)).WillReturnRows(sqlmock.NewRows([]string{"group_id", "root_id", "user_id", "origin_host", "host", "generation"}))
	entries, err := s.DispatchEntries(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || len(entries[0].Sources) != 8 || !reflect.DeepEqual(entries[0].UserIDRanges, []string{"1-9223372036854775807"}) {
		t.Fatalf("%#v", entries)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
