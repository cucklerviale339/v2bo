package admin

import (
	"reflect"
	"testing"
	"time"

	"forest/go-api/internal/platform/postgres"
)

func TestPostgresInvestigationBranchRiskRebuildAndLiveNarrowing(t *testing.T) {
	f := newInvestigationIntegration(t)
	g := f.group("range.example")
	add := func(root, group int64, kind, raw string) int64 {
		t.Helper()
		var id int64
		if err := f.db.QueryRow(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload) VALUES($1,$2,$3,100,$4) RETURNING id`, root, group, kind, raw).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	first := add(g.ID, g.ID, "filtered", `{"pulled_ids":[11,12,13],"recent_ids":[11],"older_ids":[12,13],"unpulled_ids":[14],"partitions":[{"group_id":9001,"user_ids":[11]},{"group_id":9002,"user_ids":[12,13]},{"group_id":9003,"user_ids":[14]}]}`)
	// Simulate the superseded whole-ancestor projection. Migration must remove
	// user 14 from it instead of keeping a permanent ancestral restriction.
	f.exec(`INSERT INTO v2_dispatch_risk_case(event_id,created_at) VALUES($1,100)`, first)
	f.exec(`INSERT INTO v2_dispatch_risk_member(event_id,user_id) SELECT $1,id FROM unnest(ARRAY[11,12,13,14]) id`, first)
	add(g.ID, 9004, "started", `{"user_ids":[12,13],"source_group_ids":[9002]}`)
	second := add(g.ID, 9004, "filtered", `{"pulled_ids":[12],"older_ids":[12],"unpulled_ids":[13],"risk_narrowing":{"confirmed":true,"healthy_group_ids":[9001]},"partitions":[{"group_id":9005,"user_ids":[12]},{"group_id":9003,"user_ids":[13]}]}`)
	refresh := func() {
		t.Helper()
		if err := postgres.EnsureNodeAddressSchema(f.ctx, f.db); err != nil {
			t.Fatal(err)
		}
	}
	blocked := func() []int64 {
		t.Helper()
		rows, err := f.db.Query(`SELECT user_id FROM (SELECT id AS user_id FROM v2_user) m WHERE ` + investigationRiskBlocked + ` ORDER BY user_id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		ids := []int64{}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return ids
	}
	refresh()
	if got := blocked(); !reflect.DeepEqual(got, []int64{12}) {
		t.Fatal("older recipient or narrowed ancestor incorrect", got)
	}
	var cleared int64
	if err := f.db.QueryRow(`SELECT cleared_event_id FROM v2_dispatch_risk_member WHERE event_id=$1 AND user_id=13`, first).Scan(&cleared); err != nil || cleared != second {
		t.Fatal("inherited evidence not explicitly cleared", cleared, err)
	}
	before := f.snapshot("v2_dispatch_risk_case", "v2_dispatch_risk_member", "v2_dispatch_investigation_event")
	refresh()
	if !reflect.DeepEqual(before, f.snapshot("v2_dispatch_risk_case", "v2_dispatch_risk_member", "v2_dispatch_investigation_event")) {
		t.Fatal("branch migration was not idempotent")
	}
	// Live audit uses the same reducer: an observation branch can gain new
	// evidence independently without reviving the previously cleared case.
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = investigationAudit(f.ctx, tx, g.ID, 9003, "filtered", 0, map[string]any{"pulled_ids": []int64{13}, "unpulled_ids": []int64{14}}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := blocked(); !reflect.DeepEqual(got, []int64{12, 13}) {
		t.Fatal("observation branch failed to open its own case", got)
	}
	if err = f.db.QueryRow(`SELECT cleared_event_id FROM v2_dispatch_risk_member WHERE event_id=$1 AND user_id=13`, first).Scan(&cleared); err != nil || cleared != second {
		t.Fatal("new incident revived old case", cleared, err)
	}
}

func TestPostgresInvestigationBranchRiskClockStartsAtSiblingRelease(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.enableLifecycle()
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.readyToPromote(f.group("range.example"), []int64{11, 12})
	f.exec(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload) VALUES($1,9998,'filtered',$2,jsonb_build_object('pulled_ids','[11,12,13]'::jsonb,'partitions',jsonb_build_array(jsonb_build_object('group_id',$1::bigint,'user_ids','[11,12]'::jsonb),jsonb_build_object('group_id',9999,'user_ids','[13]'::jsonb))))`, g.ID, time.Now().Unix()-500000)
	if err := postgres.EnsureNodeAddressSchema(f.ctx, f.db); err != nil {
		t.Fatal(err)
	}
	f.execProcess(g.ID)
	assertNoStage := func() {
		t.Helper()
		for _, x := range f.groups() {
			if x.LifecycleRole == "stable" {
				t.Fatal("paused time was counted", x)
			}
		}
	}
	assertNoStage()
	release := time.Now().Unix() - 86400
	var eventID int64
	if err := f.db.QueryRow(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload) VALUES($1,9999,'filtered',$2,jsonb_build_object('pulled_ids','[13]'::jsonb,'risk_narrowing',jsonb_build_object('confirmed',true,'healthy_group_ids',jsonb_build_array($1::bigint)))) RETURNING id`, g.ID, release).Scan(&eventID); err != nil {
		t.Fatal(err)
	}
	if err := postgres.EnsureNodeAddressSchema(f.ctx, f.db); err != nil {
		t.Fatal(err)
	}
	g = f.readyToPromote(f.group(g.Host), []int64{11, 12})
	f.execProcess(g.ID)
	assertNoStage()
	// Renewed pulls can preserve raw first delivery facts. Eligibility must
	// still use release_at rather than borrowing paused days from that receipt.
	var first int64
	if err := f.db.QueryRow(`SELECT first_at FROM v2_dispatch_stability_receipt WHERE user_id=11 AND host=$1`, g.Host).Scan(&first); err != nil || first < release {
		t.Fatal("personal clock was not clamped to release", first, err)
	}
	f.exec(`UPDATE v2_dispatch_investigation_event SET created_at=$2 WHERE id=$1`, eventID, time.Now().Unix()-stableObserveSeconds-100)
	if err := postgres.EnsureNodeAddressSchema(f.ctx, f.db); err != nil {
		t.Fatal(err)
	}
	g = f.readyToPromote(f.group(g.Host), []int64{11, 12})
	// The fixture moves release into the past instead of advancing wall time;
	// move the clamped personal receipt with it to model three elapsed days.
	f.exec(`UPDATE v2_dispatch_stability_receipt SET first_at=$1 WHERE host=$2 AND user_id IN(11,12)`, time.Now().Unix()-stableObserveSeconds-100, g.Host)
	f.execProcess(g.ID)
	if got := f.stageGroup("stable"); !reflect.DeepEqual(got.UserIDs, []string{"11", "12"}) {
		t.Fatal("completed post-release days did not promote", got)
	}
}

func TestPostgresInvestigationBranchRiskCorrectionIncludesPrematureReleasedAdmission(t *testing.T) {
	f := newInvestigationIntegration(t)
	root, stage := f.stageWithHistoricalRisk("stable")
	// Their candidate risk is now released, but their automatic admission did
	// not include three valid days after that release and still needs repair.
	f.exec(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload) VALUES($1,$1,'filtered',$2,'{"pulled_ids":[],"unpulled_ids":[11,12]}')`, root.ID, time.Now().Unix()-100)
	if err := postgres.EnsureNodeAddressSchema(f.ctx, f.db); err != nil {
		t.Fatal(err)
	}
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	ids, err := investigationStageCorrectionIDs(f.ctx, tx, stage)
	if err != nil || !reflect.DeepEqual(ids, []int64{11, 12}) {
		t.Fatal("premature admission treated as fully observed", ids, err)
	}
}

func TestPostgresInvestigationBranchRiskLiveConfirmationReleasesSiblingWithoutPool(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.group("range.example")
	f.exec(`DELETE FROM v2_dispatch_investigation_member WHERE group_id=$1 AND user_id NOT IN(11,12,13,14)`, g.ID)
	g = f.group(g.Host)
	f.outage(g, []int64{11, 12, 13, 14})
	f.execProcess(g.ID)
	children := []InvestigationGroup{}
	for _, x := range f.groups() {
		if x.ParentID == g.ID {
			children = append(children, x)
		}
	}
	if len(children) != 2 {
		t.Fatal("initial bisection failed", f.groups())
	}
	for _, x := range children {
		f.execProcess(x.ID)
	}
	f.exec(`UPDATE v2_dispatch_investigation_event SET created_at=created_at-1300 WHERE kind='bisected'`)
	failed := f.group(children[0].Host)
	sibling := f.group(children[1].Host)
	f.outage(failed, investigationGroupIDs(failed))
	f.execProcess(failed.ID)
	got := f.group(sibling.Host)
	if got.PromotionBlockedCount != 0 {
		t.Fatal("healthy actual sibling stayed paused while pool empty", got)
	}
	var n int
	f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_event WHERE kind='branch_fault'`).Scan(&n)
	if n != 1 {
		t.Fatal("confirmed fault not persisted", n, f.groups())
	}
	f.execProcess(failed.ID)
	f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_event WHERE kind='branch_fault'`).Scan(&n)
	if n != 1 {
		t.Fatal("pool waiting advanced clock repeatedly", n)
	}
	f.assertCheckPort(failed.Host, 18443)
}
