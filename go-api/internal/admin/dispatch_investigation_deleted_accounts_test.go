package admin

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	usersvc "forest/go-api/internal/user"
)

// Reproduce an already reassigned group whose frozen roster still contains
// deleted accounts. Completing the parent must not change those ID slots from
// an investigation address back to the original rule and fail verification.
func TestPostgresInvestigationDeletedAccountsDoNotBlockActions(t *testing.T) {
	for _, mode := range []string{"filtered", "bisected", "no_pulls", "three_buckets", "immediate", "edit"} {
		t.Run(mode, func(t *testing.T) {
			f := newInvestigationIntegration(t)
			f.exec(`INSERT INTO v2_server_vmess(id,group_id,name,host,port,server_port,rate,network,"show",created_at,updated_at) VALUES(8,'[1]','independent control','control.example','443',443,'1','tcp',1,1,1)`)
			f.save("control.example", f.pid)
			if err := f.s.bootstrapInvestigation(f.ctx); err != nil {
				t.Fatal(err)
			}
			g := f.group("range.example")
			if err := f.s.EditInvestigation(f.ctx, InvestigationEdit{ID: g.ID, Revision: g.Revision, Name: "观察", Host: "192.0.2.250"}); err != nil {
				t.Fatal(err)
			}
			g = f.group("192.0.2.250")
			f.setCheckPort(g.Host, 42822)
			f.healthyPoolPort(42822, "192.0.2.201", "192.0.2.202", "192.0.2.203")
			pulled := []int64{11, 12, 17, 42}
			switch mode {
			case "bisected":
				pulled = investigationGroupIDs(g)
			case "no_pulls":
				pulled = nil
			case "three_buckets":
				pulled = []int64{11, 12, 13, 14, 17, 42}
			}
			f.outage(g, pulled)
			if mode == "three_buckets" {
				f.exec(`UPDATE v2_dispatch_investigation_group SET epoch_at=epoch_at-8000 WHERE id=$1`, g.ID)
				f.exec(`UPDATE v2_dispatch_investigation_delivery SET delivered_at=delivered_at-7300 WHERE group_id=$1 AND user_id IN(11,12)`, g.ID)
				f.exec(`UPDATE v2_dispatch_investigation_delivery_recent SET delivered_at=delivered_at-7300 WHERE group_id=$1 AND user_id IN(11,12)`, g.ID)
			}
			f.exec(`DELETE FROM v2_user WHERE id IN(17,42)`)
			// Existing accounts remain members regardless of account eligibility.
			f.exec(`UPDATE v2_user SET banned=1,expired_at=1 WHERE id=16`)
			unchanged := []string{"v2_user", "v2_insider_rule", "v2_node_address_rule", "v2_node_address_group", "v2_node_address_binding", "v2_server_vmess", "v2_dispatch_investigation_delivery", "v2_dispatch_investigation_delivery_recent"}
			before := f.snapshot(unchanged...)
			g = f.group(g.Host)
			var err error
			switch mode {
			case "immediate":
				err = f.s.TriggerInvestigation(f.ctx, InvestigationAction{ID: g.ID, Revision: g.Revision})
			case "edit":
				err = f.s.EditInvestigation(f.ctx, InvestigationEdit{ID: g.ID, Revision: g.Revision, Name: "edited", Host: "192.0.2.249"})
			default:
				f.execProcess(g.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode != "edit" && f.successfulEvents() != 1 {
				t.Fatal("deleted roster blocked processing", f.groups())
			}
			if !reflect.DeepEqual(before, f.snapshot(unchanged...)) {
				t.Fatal("action modified source rules, account state or observation receipts")
			}
			entries, members, err := usersvc.DispatchEntriesWithInvestigationMembersFrom(f.ctx, f.db)
			if err != nil {
				t.Fatal(err)
			}
			assignments, err := usersvc.LoadInvestigationAssignments(f.ctx, f.db, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range assignments {
				if a.UserID == 17 || a.UserID == 42 {
					t.Fatal("deleted account still participates in assignment", a)
				}
			}
			for _, id := range []int64{17, 42} {
				for _, e := range entries {
					if usersvc.DispatchEntryContains(e, id) && e.Host != "range.example" && e.Host != "control.example" {
						t.Fatal("deleted account changed original configured ownership", id, e)
					}
				}
			}
			seen := map[int64]string{}
			for _, group := range f.groups() {
				if group.RootID != g.RootID {
					continue
				}
				f.assertCheckPort(group.Host, 42822)
				for id := range members[group.ID].IDs {
					if seen[id] != "" {
						t.Fatal("account assigned more than once", id)
					}
					seen[id] = group.Host
				}
			}
			u := usersvc.NewDBService(f.s.cfg, f.db)
			for _, id := range []int64{11, 12, 13, 14, 15, 16} {
				servers, err := u.Servers(f.ctx, id, "")
				if id == 16 {
					if err != nil || len(servers) != 0 || seen[id] == "" {
						t.Fatal("account eligibility changed or excluded an existing member", seen, servers, err)
					}
					continue
				}
				if err != nil || len(servers) != 2 || seen[id] == "" || fmt.Sprint(servers[0]["host"]) != seen[id] || fmt.Sprint(servers[0]["port"]) != "443" || fmt.Sprint(servers[1]["host"]) != "control.example" || seen[id] == g.Host {
					t.Fatal("wrong actual dispatch", id, seen, servers, err)
				}
			}
			if len(seen) != 6 {
				t.Fatal("wrong live roster", seen)
			}
			servers, err := u.Servers(f.ctx, 5, "")
			if err != nil || len(servers) != 2 || fmt.Sprint(servers[0]["host"]) != "base.example" || fmt.Sprint(servers[1]["host"]) != "control.example" {
				t.Fatal("unrelated account moved", servers, err)
			}
			if mode != "edit" {
				var raw []byte
				if err = f.db.QueryRow(`SELECT payload FROM v2_dispatch_investigation_event WHERE group_id=$1 AND kind IN('filtered','bisected','no_pulls')`, g.ID).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var event struct{ Partitions []investigationPartition }
				if err = json.Unmarshal(raw, &event); err != nil {
					t.Fatal(err)
				}
				wantParts := 2
				if mode == "no_pulls" {
					wantParts = 1
				}
				if mode == "three_buckets" {
					wantParts = 3
				}
				if len(event.Partitions) != wantParts {
					t.Fatal("wrong partitions", string(raw))
				}
				for _, p := range event.Partitions {
					for _, id := range p.IDs {
						if id == 17 || id == 42 {
							t.Fatal("deleted account was partitioned", p)
						}
					}
				}
				f.execProcess(g.ID)
				if f.successfulEvents() != 1 {
					t.Fatal("duplicate action")
				}
			}
		})
	}
}

func TestPostgresInvestigationDeletedAccountsCannotAutomateSingleton(t *testing.T) {
	for _, remaining := range []int{0, 1} {
		t.Run(fmt.Sprint(remaining), func(t *testing.T) {
			f := newInvestigationIntegration(t)
			g := f.group("range.example")
			if err := f.s.EditInvestigation(f.ctx, InvestigationEdit{ID: g.ID, Revision: g.Revision, Name: g.Name, Host: "192.0.2.250"}); err != nil {
				t.Fatal(err)
			}
			g = f.group("192.0.2.250")
			f.pool("192.0.2.201", "192.0.2.202")
			f.outage(g, []int64{11})
			keep := int64(0)
			if remaining == 1 {
				keep = 11
			}
			f.exec(`DELETE FROM v2_user WHERE id IN(11,12,13,14,15,16,17,42) AND id<>$1`, keep)
			tables := []string{"v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_investigation_event", "v2_dispatch_monitor", "v2_dispatch_check_target", "v2_dispatch_check_binding"}
			before := f.snapshot(tables...)
			shown, ok := f.visibleGroup(g.ID)
			if ok != (remaining == 1) || (ok && len(shown.UserIDs) != 1) {
				t.Fatal("incorrect remaining roster", shown, ok)
			}
			f.execProcess(g.ID)
			if err := f.s.TriggerInvestigation(f.ctx, InvestigationAction{ID: g.ID, Revision: g.Revision}); err == nil {
				t.Fatal("deleted accounts allowed automatic allocation for singleton/empty group")
			}
			if !reflect.DeepEqual(before, f.snapshot(tables...)) {
				t.Fatal("singleton/empty group consumed an IP or changed assignments")
			}
		})
	}
}
