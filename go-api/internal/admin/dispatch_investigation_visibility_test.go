package admin

import (
	"fmt"
	"reflect"
	"testing"

	usersvc "forest/go-api/internal/user"
)

func TestInvestigationVisibleGroupsRequireTheirOwnDispatchMembers(t *testing.T) {
	groups := []InvestigationGroup{
		{ID: 1, Host: "shared.example", UserIDs: []string{"11", "12"}},
		{ID: 2, Host: "shared.example", UserIDs: []string{"99"}},
		{ID: 3, Host: "missing.example", UserIDs: []string{"11"}},
	}
	entries := []usersvc.DispatchEntry{{Host: "shared.example", UserIDs: []string{"99"}}}
	if got := visibleInvestigationGroups(groups, entries); !reflect.DeepEqual(got, groups[1:2]) {
		t.Fatal("host presence alone exposed unrelated members", got)
	}
}

func TestPostgresInvestigationHideMissingDispatchWithoutChangingAssignments(t *testing.T) {
	for _, moved := range []bool{false, true} {
		for _, change := range []string{"rule_disabled", "node_disabled", "host_changed"} {
			t.Run(fmt.Sprintf("moved=%t/%s", moved, change), func(t *testing.T) {
				f := newInvestigationIntegration(t)
				g := f.group("range.example")
				if moved {
					if err := f.s.EditInvestigation(f.ctx, InvestigationEdit{ID: g.ID, Revision: g.Revision, Name: "观察", Host: "192.0.2.250", ManualOnly: true}); err != nil {
						t.Fatal(err)
					}
					g = f.group("192.0.2.250")
				}
				hasGroup := func() bool {
					t.Helper()
					view, err := f.s.GetInvestigation(f.ctx, 1)
					if err != nil {
						t.Fatal(err)
					}
					for _, shown := range view.Groups {
						if shown.ID == g.ID {
							return true
						}
					}
					return false
				}
				if !hasGroup() {
					t.Fatal("current dispatch group hidden")
				}
				var restore string
				switch change {
				case "rule_disabled":
					f.exec(`UPDATE v2_node_address_rule SET enabled=0 WHERE host='range.example'`)
					restore = `UPDATE v2_node_address_rule SET enabled=1 WHERE host='range.example'`
				case "node_disabled":
					f.exec(`UPDATE v2_server_vmess SET "show"=0`)
					restore = `UPDATE v2_server_vmess SET "show"=1`
				case "host_changed":
					f.exec(`UPDATE v2_node_address_rule SET host='changed.example' WHERE host='range.example'`)
					restore = `UPDATE v2_node_address_rule SET host='range.example' WHERE host='changed.example'`
				}
				// Visibility works even when the automatic worker is off.
				f.exec(`UPDATE v2_dispatch_investigation_settings SET enabled=FALSE`)
				before := f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_investigation_event", "v2_dispatch_monitor", "v2_node_address_rule", "v2_server_vmess")
				if hasGroup() {
					t.Fatal("group without dispatch ownership still shown")
				}
				if !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_investigation_event", "v2_dispatch_monitor", "v2_node_address_rule", "v2_server_vmess")) {
					t.Fatal("list read modified assignments or configuration")
				}
				f.exec(restore)
				if !hasGroup() {
					t.Fatal("restored dispatch did not restore visibility")
				}
			})
		}
	}
}
