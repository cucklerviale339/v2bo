package admin

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"forest/go-api/internal/platform/postgres"
	usersvc "forest/go-api/internal/user"
)

func (f *investigationIntegration) stageWithHistoricalRisk(role string) (InvestigationGroup, InvestigationGroup) {
	f.t.Helper()
	f.enableLifecycle()
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.readyToPromote(f.group("range.example"), []int64{11, 12, 13, 14})
	f.execProcess(g.ID)
	stage := f.stageGroup("stable")
	if role == "whitelist" {
		stage = f.readyToPromote(stage, []int64{11, 12, 13, 14})
		f.execProcess(stage.ID)
		stage = f.stageGroup("whitelist")
	}
	stage = f.readyToPromote(stage, []int64{11, 12, 13, 14})
	before := g
	before.UserIDs = []string{"11", "12"}
	raw, _ := json.Marshal(map[string]any{"before": before, "pulled_ids": []int64{11, 12}, "unpulled_ids": []int64{}})
	f.exec(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload) VALUES($1,$1,'filtered',$2,$3)`, g.ID, time.Now().Unix()-90000, string(raw))
	if err := postgres.EnsureNodeAddressSchema(f.ctx, f.db); err != nil {
		f.t.Fatal(err)
	}
	return g, f.group(stage.Host)
}

func TestPostgresLifecycleCorrectionMovesOnlyAutomaticRiskAndPreservesProgress(t *testing.T) {
	for _, role := range []string{"stable", "whitelist"} {
		t.Run(role, func(t *testing.T) {
			f := newInvestigationIntegration(t)
			f.exec(`INSERT INTO v2_server_vmess(id,group_id,name,host,port,server_port,rate,network,"show",created_at,updated_at) VALUES(8,'[1]','other scope','other.example','8443',8443,'1','tcp',1,1,1)`)
			_, stage := f.stageWithHistoricalRisk(role)
			f.exec(`UPDATE v2_dispatch_check_target SET enabled=FALSE WHERE kind='pool'`)
			f.poolAtPort(23135, "192.0.2.213")
			// User 12 was explicitly removed/re-added by an administrator after
			// the automatic admission. This latest manual decision takes priority.
			f.exec(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload) VALUES($1,$2,'edited',$3,'{"added_ids":[12]}')`, stage.RootID, stage.ID, time.Now().Unix())
			progress := f.snapshot("v2_dispatch_stability_receipt")
			f.execProcess(stage.ID)
			after := f.group(stage.Host)
			if !reflect.DeepEqual(after.UserIDs, []string{"12", "13", "14"}) || after.NormalSince != stage.NormalSince || after.Generation != stage.Generation || after.EpochAt != stage.EpochAt || !reflect.DeepEqual(after.NormalCheckpoints, stage.NormalCheckpoints) {
				t.Fatal("unaffected or manual member evidence changed", stage, after)
			}
			var target InvestigationGroup
			for _, g := range f.groups() {
				if g.ParentID == stage.ID && g.LifecycleRole == "ordinary" && reflect.DeepEqual(g.UserIDs, []string{"11"}) {
					target = g
				}
			}
			if target.ID == 0 || target.Kind != "observation" || target.ManualOnly || target.Host == stage.Host || target.ReadyAt != 0 {
				t.Fatal("risk was not moved to independent observation", f.groups())
			}
			f.assertCheckPort(target.Host, 23135)
			f.assertCheckPort(stage.Host, 18443)
			f.assertUserHosts(11, target.Host, "other.example")
			for _, id := range []int64{12, 13, 14} {
				f.assertUserHosts(id, stage.Host, "other.example")
			}
			u := usersvc.NewDBService(f.s.cfg, f.db)
			nodes, err := u.Servers(f.ctx, 11, "")
			if err != nil || len(nodes) != 2 || fmt.Sprint(nodes[0]["host"]) != target.Host || fmt.Sprint(nodes[1]["host"]) != "other.example" || fmt.Sprint(nodes[1]["port"]) != "8443" {
				t.Fatal("business scope was broadened", nodes, err)
			}
			if reflect.DeepEqual(progress, f.snapshot("v2_dispatch_stability_receipt")) {
				t.Fatal("moved user's old stability progress was retained")
			}
			var receipts int
			f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_stability_receipt WHERE user_id IN(12,13,14) AND host=$1`, stage.Host).Scan(&receipts)
			if receipts != 3 {
				t.Fatal("remaining personal progress was deleted", receipts)
			}
			f.execProcess(stage.ID)
			var events int
			f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_event WHERE kind='stage_corrected'`).Scan(&events)
			if events != 1 {
				t.Fatal("correction replayed", events)
			}
		})
	}
}

func TestPostgresLifecycleCorrectionPoolWaitAndRollback(t *testing.T) {
	f := newInvestigationIntegration(t)
	_, stage := f.stageWithHistoricalRisk("whitelist")
	before := f.snapshot("v2_dispatch_investigation_member", "v2_dispatch_stability_receipt", "v2_dispatch_monitor")
	f.execProcess(stage.ID)
	if !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_member", "v2_dispatch_stability_receipt", "v2_dispatch_monitor")) {
		t.Fatal("correction without pool changed routing or receipts")
	}
	f.poolAtPort(23135, "192.0.2.213")
	f.exec(`ALTER TABLE v2_dispatch_investigation_event ADD CONSTRAINT reject_correction_test CHECK(kind<>'stage_corrected')`)
	f.execProcess(stage.ID)
	if !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_member", "v2_dispatch_stability_receipt", "v2_dispatch_monitor")) {
		t.Fatal("failed correction partially committed")
	}
	f.exec(`ALTER TABLE v2_dispatch_investigation_event DROP CONSTRAINT reject_correction_test`)
	f.execProcess(stage.ID)
	if !reflect.DeepEqual(f.group(stage.Host).UserIDs, []string{"13", "14"}) {
		t.Fatal("refill/retry did not finish correction", f.groups())
	}
}

func TestPostgresLifecycleCorrectionWaitKeepsRestartAndObservationLive(t *testing.T) {
	f := newInvestigationIntegration(t)
	_, stage := f.stageWithHistoricalRisk("stable")
	f.exec(`UPDATE v2_dispatch_check_target SET enabled=FALSE WHERE kind='pool'`)
	f.restartWithEvidence()
	task := f.tasks(f.pid)[stage.Host]
	f.report(f.pid, task, time.Now().UnixNano(), 1, 0)
	beforeMembers := f.snapshot("v2_dispatch_investigation_member")
	f.execProcess(stage.ID)
	after := f.group(stage.Host)
	var checkpoints map[int64]normalCheckpoint
	if err := json.Unmarshal(after.NormalCheckpoints, &checkpoints); err != nil {
		t.Fatal(err)
	}
	if after.ConfigKey == stage.ConfigKey || checkpoints[f.pid].RunID != task.RunID || after.Generation != stage.Generation || !strings.HasPrefix(after.Reason, "待纠正 2 名") {
		t.Fatal("pending correction prevented restart reconciliation", stage, after, checkpoints)
	}
	if after.NormalSince < stage.NormalSince || after.NormalSince > stage.NormalSince+100 || !reflect.DeepEqual(beforeMembers, f.snapshot("v2_dispatch_investigation_member")) {
		t.Fatal("waiting changed roster or erased healthy observation", stage, after)
	}
	var promoted int
	f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_event WHERE kind='whitelist_promoted'`).Scan(&promoted)
	if promoted != 0 {
		t.Fatal("stage bypassed pending correction")
	}
}

func TestPostgresLifecycleCorrectionWaitStillConfirmsFault(t *testing.T) {
	f := newInvestigationIntegration(t)
	_, stage := f.stageWithHistoricalRisk("stable")
	f.exec(`UPDATE v2_dispatch_check_target SET enabled=FALSE WHERE kind='pool'`)
	// Start a new continuous fixture span after the synthetic seven-day
	// promotion history, rather than mixing its old timestamps into this fault.
	f.exec(`DELETE FROM v2_dispatch_history WHERE source='entry' AND target_id=$1`, stage.MonitorID)
	f.outage(stage, []int64{11, 12})
	before := f.snapshot("v2_dispatch_investigation_member")
	f.execProcess(stage.ID)
	after := f.group(stage.Host)
	var confirmed int
	if err := f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_event WHERE group_id=$1 AND kind='branch_fault'`, stage.ID).Scan(&confirmed); err != nil || confirmed != 1 {
		t.Fatal("correction wait blocked confirmed fault handling", confirmed, err, after)
	}
	if after.NormalSince != 0 || !strings.HasPrefix(after.Reason, "等待 ") || !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_member")) {
		t.Fatal("fault wait did not preserve routing and clear healthy observation", after)
	}
}

func TestPostgresLifecycleCorrectionLeavesOverriddenMembersAndHonorsSwitch(t *testing.T) {
	f := newInvestigationIntegration(t)
	_, stage := f.stageWithHistoricalRisk("stable")
	f.overrideMembers([]string{"11"})
	f.pool("192.0.2.213")
	f.exec(`UPDATE v2_dispatch_investigation_settings SET lifecycle_enabled=FALSE`)
	before := f.snapshot("v2_dispatch_investigation_member")
	f.execProcess(stage.ID)
	if !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_member")) {
		t.Fatal("disabled lifecycle corrected routing")
	}
	f.exec(`UPDATE v2_dispatch_investigation_settings SET lifecycle_enabled=TRUE`)
	f.execProcess(stage.ID)
	f.assertUserHosts(11, "override.example")
	var groupID int64
	f.db.QueryRow(`SELECT group_id FROM v2_dispatch_investigation_member WHERE origin_host='range.example' AND user_id=11`).Scan(&groupID)
	if groupID != stage.ID {
		t.Fatal("overridden membership was moved")
	}
	if !reflect.DeepEqual(f.group(stage.Host).UserIDs, []string{"11", "13", "14"}) {
		t.Fatal("wrong stored members", f.groups())
	}
}

func TestPostgresLifecycleCorrectionLargeRosterAcrossPorts(t *testing.T) {
	f := newInvestigationIntegration(t)
	_, stage := f.stageWithHistoricalRisk("stable")
	f.exec(`INSERT INTO v2_user(id,email,password,uuid,token,group_id,plan_id,transfer_enable,created_at,updated_at) SELECT id,'large-'||id||'@example.test','hash','00000000-0000-0000-0000-'||lpad(id::text,12,'0'),lpad(id::text,32,'0'),1,1,1000000,1,1 FROM generate_series(1001,2400) id`)
	f.exec(`UPDATE v2_node_address_rule SET match_user_id_ranges='["11-2400"]' WHERE host='range.example'`)
	f.exec(`INSERT INTO v2_dispatch_investigation_member(root_id,user_id,group_id,origin_host) SELECT $1,id,$2,'range.example' FROM generate_series(1001,2400) id`, stage.RootID, stage.ID)
	// Two hundred separate promotion batches, resembling the production
	// history. Every recipient is concrete; a last manual admission wins.
	f.exec(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload)
SELECT $1,$1,'stable_promoted',1,jsonb_build_object('target_group_id',$2::bigint,'user_ids',jsonb_agg(id)) FROM generate_series(1001,2400) id GROUP BY (id-1001)/7`, stage.RootID, stage.ID)
	f.exec(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload) VALUES($1,$2,'edited',2,'{"added_ids":[1001,1002,1003,1004,1005,1006,1007,1008,1009,1010,1011,1012,1013,1014,1015,1016,1017,1018,1019,1020,1021]}')`, stage.RootID, stage.ID)
	f.exec(`WITH e AS(INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload) SELECT $1,$1,'filtered',1,jsonb_build_object('pulled_ids',jsonb_agg(id)) FROM generate_series(1001,2400) id RETURNING id),c AS(INSERT INTO v2_dispatch_risk_case(event_id,created_at) SELECT id,1 FROM e RETURNING event_id)
INSERT INTO v2_dispatch_risk_member(event_id,user_id) SELECT event_id,id FROM c CROSS JOIN generate_series(1001,2400) id`, stage.RootID)
	f.exec(`UPDATE v2_dispatch_check_target SET enabled=FALSE WHERE kind='pool'`)
	f.poolAtPort(23130, "192.0.2.213")
	f.execProcess(stage.ID)
	remaining := f.group(stage.Host)
	if len(remaining.UserIDs) != 23 { // 21 explicit manual + clean users 13,14.
		t.Fatal("large correction lost manual or clean members", len(remaining.UserIDs), remaining.Reason)
	}
	var moved int
	if err := f.db.QueryRow(`SELECT jsonb_array_length(payload->'user_ids') FROM v2_dispatch_investigation_event WHERE kind='stage_corrected'`).Scan(&moved); err != nil || moved != 1381 {
		t.Fatal("large correction did not commit the full roster", moved, err)
	}
	f.assertCheckPort("192.0.2.213", 23130)
	f.assertCheckPort(stage.Host, 18443)
}

func TestPostgresLifecycleCorrectionHoldSurvivesHealthyDaysAndRestarts(t *testing.T) {
	f := newInvestigationIntegration(t)
	root, stage := f.stageWithHistoricalRisk("stable")
	f.exec(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload) VALUES($1,$1,'members_moved',$3,jsonb_build_object('user_ids','[11,12]'::jsonb,'target_group_id',$2::bigint))`, root.ID, stage.ID, time.Now().Unix()-60)
	f.pool("192.0.2.213", "192.0.2.214", "192.0.2.215")
	f.execProcess(stage.ID)
	var target InvestigationGroup
	for _, g := range f.groups() {
		if g.ParentID == stage.ID && g.LifecycleRole == "ordinary" {
			target = g
		}
	}
	if target.ID == 0 || target.Name != "待复核" || !target.RosterFrozen || !reflect.DeepEqual(target.UserIDs, []string{"11", "12"}) {
		t.Fatal("correction did not create one frozen review roster", target)
	}
	// An unconfirmed/manual no-pull decision may clear ordinary ancestor
	// evidence, but cannot end the explicit correction hold.
	raw, _ := json.Marshal(map[string]any{"unpulled_ids": []int64{11, 12}, "evidence": map[string]any{"mode": "manual"}})
	f.exec(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload) VALUES($1,$2,'no_pulls',$3,$4)`, target.RootID, target.ID, time.Now().Unix()-4*86400, string(raw))
	for i := 0; i < 2; i++ {
		if err := postgres.EnsureNodeAddressSchema(f.ctx, f.db); err != nil {
			t.Fatal(err)
		}
		tx, err := f.db.BeginTx(f.ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		held, err := investigationPromotionHeld(f.ctx, tx, target.ID)
		tx.Rollback()
		if err != nil || !held {
			t.Fatal("hold lost after replay", held, err)
		}
		target = f.readyToPromote(f.group(target.Host), []int64{11, 12})
		f.execProcess(target.ID)
		got := f.group(target.Host)
		if got.PromotionBlockedCount != 2 || !reflect.DeepEqual(got.UserIDs, []string{"11", "12"}) || got.Reason != "独立复核中，确认故障并完成细分前不参与晋级" {
			t.Fatal("healthy days promoted the held roster", got)
		}
		if !reflect.DeepEqual(f.group(stage.Host).UserIDs, []string{"13", "14"}) {
			t.Fatal("held users rejoined stable stage", f.groups())
		}
	}
	// This roster is neither an auto-merge source nor destination, even when
	// ordinary observation groups use a healthy entrance in the same root.
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	merge, err := f.s.healthyObservation(f.ctx, tx, target, f.groups())
	if err != nil || merge != nil {
		t.Fatal("review roster merged into ordinary observation", merge, err)
	}
}

func TestPostgresLifecycleCorrectionHoldConfirmedSplitCommitsAtomically(t *testing.T) {
	f := newInvestigationIntegration(t)
	root, stage := f.stageWithHistoricalRisk("stable")
	// The helper injects past risk after constructing the stage. Supply its
	// concrete move so replay follows the same chronological lineage as live data.
	f.exec(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload) VALUES($1,$1,'members_moved',$3,jsonb_build_object('user_ids','[11,12]'::jsonb,'target_group_id',$2::bigint))`, root.ID, stage.ID, time.Now().Unix()-60)
	f.pool("192.0.2.213", "192.0.2.214", "192.0.2.215")
	f.execProcess(stage.ID)
	var target InvestigationGroup
	for _, g := range f.groups() {
		if g.ParentID == stage.ID && g.LifecycleRole == "ordinary" {
			target = g
		}
	}
	if target.ID == 0 {
		t.Fatal("missing review roster")
	}
	f.outage(target, []int64{11})
	f.exec(`ALTER TABLE v2_dispatch_investigation_event ADD CONSTRAINT reject_hold_partition CHECK(kind<>'filtered') NOT VALID`)
	before := f.snapshot("v2_dispatch_investigation_member", "v2_dispatch_risk_case", "v2_dispatch_risk_member")
	f.execProcess(target.ID)
	if !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_member", "v2_dispatch_risk_case", "v2_dispatch_risk_member")) {
		t.Fatal("failed partition released hold or moved users")
	}
	if f.group(target.Host).PromotionHoldCount != 2 {
		t.Fatal("rollback erased hold")
	}
	f.exec(`ALTER TABLE v2_dispatch_investigation_event DROP CONSTRAINT reject_hold_partition`)
	f.execProcess(target.ID)
	var observer, confirmed InvestigationGroup
	for _, g := range f.groups() {
		if g.ParentID != target.ID {
			continue
		}
		if reflect.DeepEqual(g.UserIDs, []string{"12"}) {
			observer = g
		}
		if reflect.DeepEqual(g.UserIDs, []string{"11"}) {
			confirmed = g
		}
	}
	if observer.ID == 0 || observer.Kind != "observation" || observer.PromotionHoldCount != 0 || observer.PromotionBlockedCount != 0 || observer.Host == target.Host {
		t.Fatal("confirmed non-recipient branch did not restart observation", f.groups())
	}
	if confirmed.ID == 0 || confirmed.Kind != "confirmed" || !confirmed.ManualOnly || confirmed.PromotionBlockedCount != 1 {
		t.Fatal("sole-recipient evidence did not remain locked", confirmed)
	}
	f.assertCheckPort(observer.Host, 18443)
	f.assertUserHosts(12, observer.Host)
	if !reflect.DeepEqual(f.group(stage.Host).UserIDs, []string{"13", "14"}) {
		t.Fatal("unrelated stable users changed")
	}
}
