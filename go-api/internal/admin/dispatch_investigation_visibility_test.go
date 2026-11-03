package admin

import (
	"encoding/json"
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
		{ID: 4, Host: "old.example", UserIDs: []string{"11"}},
	}
	members := map[int64]usersvc.InvestigationMembers{2: {Host: "shared.example", IDs: map[int64]bool{99: true}}}
	members[4] = usersvc.InvestigationMembers{Host: "new.example", IDs: map[int64]bool{11: true}}
	if got := currentInvestigationGroups(groups, members); !reflect.DeepEqual(got, groups[1:2]) {
		t.Fatal("host presence alone exposed unrelated members", got)
	}
}

func TestPostgresInvestigationRechecksOwnershipBeforeAllocatingPool(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.group("range.example")
	f.outage(g, []int64{11, 12, 13})
	g = f.group(g.Host)
	before, members, err := usersvc.DispatchEntriesWithInvestigationMembersFrom(f.ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	g = currentInvestigationGroups([]InvestigationGroup{g}, members)[0]
	// A higher-priority writer wins after preliminary evidence was read.
	f.overrideMembers([]string{"11"})
	snapshot := f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_investigation_event", "v2_dispatch_monitor")
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	reason := ""
	err = f.s.applyInvestigation(f.ctx, tx, g, nil, investigationEvidence{}, before, 600, func(v string) error { reason = v; return nil })
	if err != nil || reason != "下发规则发生变化，等待重新确认" {
		t.Fatal(reason, err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(snapshot, f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_investigation_event", "v2_dispatch_monitor")) {
		t.Fatal("stale operation modified assignments or monitors")
	}
}

func (f *investigationIntegration) overrideMembers(ids []string) {
	f.t.Helper()
	raw, _ := json.Marshal(ids)
	f.exec(`INSERT INTO v2_insider_rule(host,match_user_ids,enabled,created_at,updated_at) VALUES('override.example',$1,1,1,1)`, string(raw))
}

func (f *investigationIntegration) visibleGroup(id int64) (InvestigationGroup, bool) {
	f.t.Helper()
	v, err := f.s.GetInvestigation(f.ctx, 1)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, g := range v.Groups {
		if g.ID == id {
			return g, true
		}
	}
	return InvestigationGroup{}, false
}

func TestPostgresInvestigationPartialOwnershipContinuesWithoutMovingOverride(t *testing.T) {
	for _, mode := range []string{"filtered", "bisected", "no_pulls", "immediate"} {
		t.Run(mode, func(t *testing.T) {
			f := newInvestigationIntegration(t)
			f.pool("192.0.2.211", "192.0.2.212")
			g := f.group("range.example")
			pulled := []int64{11, 12, 13}
			if mode == "bisected" {
				pulled = investigationGroupIDs(g)
			}
			if mode == "no_pulls" {
				pulled = nil
			}
			f.outage(g, pulled)
			f.overrideMembers([]string{"11"})
			before := f.snapshot("v2_insider_rule", "v2_node_address_rule", "v2_server_vmess")
			shown, ok := f.visibleGroup(g.ID)
			if !ok || len(shown.UserIDs) != 7 || !reflect.DeepEqual(shown.ExcludedUserIDs, []string{"11"}) {
				t.Fatal(shown)
			}
			if mode == "immediate" {
				if err := f.s.TriggerInvestigation(f.ctx, InvestigationAction{ID: shown.ID, Revision: shown.Revision}); err != nil {
					t.Fatal(err)
				}
			} else {
				f.execProcess(g.ID)
			}
			if f.successfulEvents() != 1 {
				t.Fatal("partial ownership blocked processing", f.groups())
			}
			servers, err := usersvc.NewDBService(f.s.cfg, f.db).Servers(f.ctx, 11, "")
			if err != nil || len(servers) == 0 || fmt.Sprint(servers[0]["host"]) != "override.example" || fmt.Sprint(servers[0]["port"]) != "443" {
				t.Fatal(servers, err)
			}
			if !reflect.DeepEqual(before, f.snapshot("v2_insider_rule", "v2_node_address_rule", "v2_server_vmess")) {
				t.Fatal("original dispatch rules changed")
			}
			var raw []byte
			if err := f.db.QueryRow(`SELECT payload FROM v2_dispatch_investigation_event WHERE group_id=$1 AND kind IN('filtered','bisected','no_pulls')`, g.ID).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var event struct {
				Before     InvestigationGroup
				Partitions []investigationPartition
			}
			if err := json.Unmarshal(raw, &event); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(event.Before.ExcludedUserIDs, []string{"11"}) {
				t.Fatal("missing exclusion audit", string(raw))
			}
			count := 0
			for _, p := range event.Partitions {
				f.assertCheckPort(p.Host, 18443)
				for _, id := range p.IDs {
					if id == 11 {
						t.Fatal("override was repartitioned")
					}
					count++
				}
			}
			if count != 7 {
				t.Fatal("incorrect effective member count", count)
			}
		})
	}
}

func TestPostgresInvestigationEffectiveSingletonAndNoMembersCannotAutomate(t *testing.T) {
	for _, remaining := range []int{0, 1} {
		t.Run(fmt.Sprint(remaining), func(t *testing.T) {
			f := newInvestigationIntegration(t)
			g := f.group("range.example")
			f.outage(g, nil)
			f.overrideMembers(g.UserIDs[remaining:])
			before := f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_investigation_event", "v2_dispatch_monitor")
			shown, ok := f.visibleGroup(g.ID)
			if ok != (remaining > 0) || (ok && len(shown.UserIDs) != 1) {
				t.Fatal(shown, ok)
			}
			f.execProcess(g.ID)
			g = f.group(g.Host)
			a := InvestigationAction{ID: g.ID, Revision: g.Revision}
			if f.s.ConfirmInvestigation(f.ctx, a) == nil || f.s.TriggerInvestigation(f.ctx, a) == nil {
				t.Fatal("effective singleton/no members bypassed guards")
			}
			if err := f.s.EditInvestigation(f.ctx, InvestigationEdit{ID: g.ID, Revision: g.Revision, Name: g.Name, Host: g.Host, ManualOnly: false}); err == nil {
				t.Fatal("effective singleton enabled automation")
			}
			if !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_investigation_event", "v2_dispatch_monitor")) {
				t.Fatal("guard mutated stored assignments")
			}
		})
	}
}

func TestPostgresInvestigationPartialOwnershipConfirmAndEdit(t *testing.T) {
	for _, mode := range []string{"confirm", "edit"} {
		t.Run(mode, func(t *testing.T) {
			f := newInvestigationIntegration(t)
			g := f.group("range.example")
			f.outage(g, nil)
			f.overrideMembers([]string{"11"})
			g = f.group(g.Host)
			var err error
			if mode == "confirm" {
				err = f.s.ConfirmInvestigation(f.ctx, InvestigationAction{ID: g.ID, Revision: g.Revision})
			} else {
				err = f.s.EditInvestigation(f.ctx, InvestigationEdit{ID: g.ID, Revision: g.Revision, Name: "edited", Host: "192.0.2.250"})
			}
			if err != nil {
				t.Fatal(err)
			}
			servers, err := usersvc.NewDBService(f.s.cfg, f.db).Servers(f.ctx, 11, "")
			if err != nil || len(servers) == 0 || fmt.Sprint(servers[0]["host"]) != "override.example" {
				t.Fatal(servers, err)
			}
			shown, ok := f.visibleGroup(g.ID)
			if !ok || len(shown.UserIDs) != 7 {
				t.Fatal(shown)
			}
		})
	}
}

func TestPostgresInvestigationMatchingDestinationCannotReplaceOriginalSource(t *testing.T) {
	f := newInvestigationIntegration(t)
	g := f.group("range.example")
	if err := f.s.EditInvestigation(f.ctx, InvestigationEdit{ID: g.ID, Revision: g.Revision, Name: g.Name, Host: "192.0.2.250"}); err != nil {
		t.Fatal(err)
	}
	f.overrideMembers([]string{"11"})
	// The final IP stays identical, but the higher-priority rule, rather than
	// this group's original source, now owns user 11.
	f.exec(`UPDATE v2_insider_rule SET host='192.0.2.250'`)
	shown, ok := f.visibleGroup(g.ID)
	if !ok || len(shown.UserIDs) != 7 || !reflect.DeepEqual(shown.ExcludedUserIDs, []string{"11"}) {
		t.Fatal("destination match admitted a member from another source", shown)
	}
	f.exec(`UPDATE v2_insider_rule SET enabled=0`)
	shown, ok = f.visibleGroup(g.ID)
	if !ok || len(shown.UserIDs) != 8 || len(shown.ExcludedUserIDs) != 0 {
		t.Fatal("source restoration did not restore effective membership", shown)
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
