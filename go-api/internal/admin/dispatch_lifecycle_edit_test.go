package admin

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	usersvc "forest/go-api/internal/user"
)

func lifecycleEditRequest(g InvestigationGroup, ids ...string) InvestigationEdit {
	return InvestigationEdit{ID: g.ID, Revision: g.Revision, Name: g.Name, Host: g.Host, Policy: g.Policy, ManualOnly: g.ManualOnly, UserIDs: &ids}
}

func (f *investigationIntegration) assertUserHosts(id int64, hosts ...string) {
	f.t.Helper()
	nodes, err := usersvc.NewDBService(f.s.cfg, f.db).Servers(f.ctx, id, "")
	if err != nil {
		f.t.Fatal(err)
	}
	got := map[string]bool{}
	for _, node := range nodes {
		got[fmt.Sprint(node["host"])] = true
	}
	want := map[string]bool{}
	for _, host := range hosts {
		want[host] = true
	}
	if !reflect.DeepEqual(got, want) {
		f.t.Fatalf("user %d hosts: %v, want %v", id, got, want)
	}
}

func TestPostgresLifecycleEditMembersPreservesScopeAndPersonalClocks(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.enableLifecycle()
	f.pool("192.0.2.211")
	f.exec(`INSERT INTO v2_server_vmess(id,group_id,name,host,port,server_port,rate,network,"show",created_at,updated_at) VALUES(8,'[1]','unrelated','other.example','8443',8443,'1','tcp',1,1,1)`)
	g := f.readyToPromote(f.group("range.example"), []int64{11, 12, 13})
	f.execProcess(g.ID)
	stable := f.readyToPromote(f.stageGroup("stable"), []int64{11, 12, 13})
	var first int64
	if err := f.db.QueryRow(`SELECT first_at FROM v2_dispatch_stability_receipt WHERE origin_host='range.example' AND user_id=11`).Scan(&first); err != nil {
		t.Fatal(err)
	}
	source := f.group("range.example")
	request := lifecycleEditRequest(stable, "14", "11", "11")
	if err := f.s.EditInvestigation(f.ctx, request); err != nil {
		t.Fatal(err)
	}
	after := f.group(stable.Host)
	if !reflect.DeepEqual(after.UserIDs, []string{"11", "14"}) || after.Generation != stable.Generation+1 || after.NormalSince != stable.NormalSince || after.LifecycleRole != "stable" {
		t.Fatal("membership edit lost established observation", stable, after)
	}
	if f.group("range.example").Revision <= source.Revision {
		t.Fatal("source editor was not invalidated")
	}
	f.assertUserHosts(11, stable.Host, "other.example")
	f.assertUserHosts(14, stable.Host, "other.example")
	f.assertUserHosts(12, "range.example", "other.example")
	f.assertUserHosts(13, "range.example", "other.example")
	var retained, cleared int64
	f.db.QueryRow(`SELECT first_at FROM v2_dispatch_stability_receipt WHERE origin_host='range.example' AND user_id=11`).Scan(&retained)
	f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_stability_receipt WHERE origin_host='range.example' AND user_id IN(12,13,14)`).Scan(&cleared)
	if retained != first || cleared != 0 {
		t.Fatal("retained or newcomer clock incorrect", first, retained, cleared)
	}
	// A response prepared before the edit cannot credit the new member's round.
	u := usersvc.NewDBService(f.s.cfg, f.db)
	if err := u.RecordInvestigationDelivery(f.ctx, 14, []usersvc.InvestigationDelivery{{GroupID: stable.ID, Generation: stable.Generation, Host: stable.Host}}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_stability_receipt WHERE origin_host='range.example' AND user_id=14`).Scan(&cleared)
	if cleared != 0 {
		t.Fatal("late response credited a newly moved user")
	}
	if err := u.RecordInvestigationDelivery(f.ctx, 14, []usersvc.InvestigationDelivery{{GroupID: after.ID, Generation: after.Generation, Host: after.Host}}, time.Now().Unix()+1); err != nil {
		t.Fatal(err)
	}
	var entrant int64
	if err := f.db.QueryRow(`SELECT first_at FROM v2_dispatch_stability_receipt WHERE origin_host='range.example' AND user_id=14`).Scan(&entrant); err != nil || entrant <= first {
		t.Fatal("new member borrowed old observation", entrant, first, err)
	}
	if err := f.s.EditInvestigation(f.ctx, request); !errors.Is(err, ErrDNSProbeInvalidRequest) {
		t.Fatal("stale edit accepted", err)
	}
	// The worker may receive released users into their ordinary business root,
	// but must never add them directly back to the frozen stable roster.
	if err := f.s.bootstrapInvestigation(f.ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.group(after.Host).UserIDs, after.UserIDs) {
		t.Fatal("released member rejoined stage")
	}
	rejoin := lifecycleEditRequest(f.group(after.Host), "11", "12", "14")
	if err := f.s.EditInvestigation(f.ctx, rejoin); err != nil {
		t.Fatal(err)
	}
	f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_stability_receipt WHERE user_id=12 AND origin_host='range.example'`).Scan(&cleared)
	if cleared != 0 || f.group(after.Host).NormalSince != after.NormalSince {
		t.Fatal("returning member reused previous stage time or reset existing members")
	}
}

func TestPostgresLifecycleEditCrossOriginAndReleasePreservesReceiver(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.enableLifecycle()
	f.pool("192.0.2.211")
	g := f.readyToPromote(f.group("range.example"), []int64{11, 12})
	f.execProcess(g.ID)
	stable := f.stageGroup("stable")
	if err := f.s.EditInvestigation(f.ctx, lifecycleEditRequest(stable, "5", "11", "12")); err != nil {
		t.Fatal(err)
	}
	f.assertUserHosts(5, stable.Host)
	if f.group("base.example").ManualOnly {
		t.Fatal("temporary singleton permanently disabled the original receiving root")
	}
	stable = f.group(stable.Host)
	if err := f.s.EditInvestigation(f.ctx, lifecycleEditRequest(stable, "11", "12")); err != nil {
		t.Fatal(err)
	}
	f.assertUserHosts(5, "base.example")
	if err := f.s.bootstrapInvestigation(f.ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.group("base.example").UserIDs, []string{"5", "150"}) {
		t.Fatal("released user did not resume ordinary observation", f.group("base.example"))
	}
}

func TestPostgresLifecycleEditWhitelistHostAndReturningMember(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.enableLifecycle()
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.readyToPromote(f.group("range.example"), []int64{11, 12, 13})
	f.execProcess(g.ID)
	stable := f.readyToPromote(f.stageGroup("stable"), []int64{11, 12, 13})
	f.execProcess(stable.ID)
	white := f.stageGroup("whitelist")
	request := lifecycleEditRequest(white, "11", "12", "14")
	request.Host = "192.0.2.220"
	if err := f.s.EditInvestigation(f.ctx, request); err != nil {
		t.Fatal(err)
	}
	after := f.group(request.Host)
	if after.LifecycleRole != "whitelist" || after.NormalSince != 0 || after.ReadyAt != 0 || after.Generation != white.Generation+1 {
		t.Fatal(after)
	}
	var port, receipts int64
	f.db.QueryRow(`SELECT check_port FROM v2_dispatch_monitor WHERE id=$1`, after.MonitorID).Scan(&port)
	f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_stability_receipt WHERE user_id IN(11,12,13,14)`).Scan(&receipts)
	if port != 18443 || receipts != 0 {
		t.Fatal("manual move changed detection port or reused old receipt", port, receipts)
	}
	f.assertUserHosts(11, request.Host)
	f.assertUserHosts(14, request.Host)
	f.assertUserHosts(13, "range.example")
	// Returning to the former endpoint can recycle its unused monitor, but
	// cannot recycle the stability clock or the old probe identity.
	back := lifecycleEditRequest(after, "11", "12", "14")
	back.Host = white.Host
	if err := f.s.EditInvestigation(f.ctx, back); err != nil {
		t.Fatal(err)
	}
	returned := f.group(back.Host)
	if returned.MonitorID == white.MonitorID || returned.NormalSince != 0 {
		t.Fatal("old endpoint evidence was resurrected", returned)
	}
	// A manually reduced roster is not evidence of a sole-recipient fault.
	single := lifecycleEditRequest(returned, "11")
	if err := f.s.EditInvestigation(f.ctx, single); err != nil {
		t.Fatal(err)
	}
	if f.group(back.Host).ManualOnly {
		t.Fatal("unproven singleton observation was disabled")
	}
	f.assertUserHosts(12, "range.example")
}

func TestPostgresLifecycleEditValidationAndRollback(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.enableLifecycle()
	f.pool("192.0.2.211")
	g := f.readyToPromote(f.group("range.example"), []int64{11, 12})
	f.execProcess(g.ID)
	stable := f.stageGroup("stable")
	before, err := usersvc.DispatchEntriesFrom(f.ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	for _, ids := range [][]string{{}, {"11-12"}, {"11", "999999"}, {"11", "-1"}} {
		request := lifecycleEditRequest(stable, ids...)
		request.Host = "192.0.2.221"
		if err := f.s.EditInvestigation(f.ctx, request); !errors.Is(err, ErrDNSProbeInvalidRequest) {
			t.Fatal("invalid members accepted", ids, err)
		}
	}
	ordinary := f.group("range.example")
	if err := f.s.EditInvestigation(f.ctx, lifecycleEditRequest(ordinary, "13", "14")); !errors.Is(err, ErrDNSProbeInvalidRequest) {
		t.Fatal("ordinary member editing unexpectedly enabled", err)
	}
	var leaked int64
	f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_monitor WHERE host='192.0.2.221'`).Scan(&leaked)
	after, err := usersvc.DispatchEntriesFrom(f.ctx, f.db)
	if err != nil || leaked != 0 || !reflect.DeepEqual(before, after) || f.group(stable.Host).Revision != stable.Revision {
		t.Fatal("invalid edit partially committed", leaked, err)
	}
	// A failing write after the member transfer must restore memberships,
	// personal receipts and the newly cloned monitor together.
	f.exec(`ALTER TABLE v2_dispatch_investigation_group ADD CONSTRAINT reject_manual_name CHECK(name<>'reject-edit')`)
	request := lifecycleEditRequest(stable, "11", "14")
	request.Name, request.Host = "reject-edit", "192.0.2.221"
	if err := f.s.EditInvestigation(f.ctx, request); err == nil {
		t.Fatal("expected write failure")
	}
	after, err = usersvc.DispatchEntriesFrom(f.ctx, f.db)
	f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_monitor WHERE host='192.0.2.221'`).Scan(&leaked)
	if err != nil || leaked != 0 || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(f.group(stable.Host).UserIDs, stable.UserIDs) {
		t.Fatal("failed write partially committed", leaked, err)
	}
}
