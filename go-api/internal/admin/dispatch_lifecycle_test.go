package admin

import (
	"encoding/json"
	"fmt"
	usersvc "forest/go-api/internal/user"
	"reflect"
	"testing"
	"time"
)

func TestLifecycleProgressPausesWithoutErasingObservation(t *testing.T) {
	p := investigationProbe{dispatchSplitCandidate: dispatchSplitCandidate{Version: 1, RunID: 2, Sequence: 30, Reported: 1900, Interval: 30, Timeout: 500, Success: true}}
	old := normalCheckpoint{1, 1, 10, 1000}
	samples := []DispatchHistorySample{{Version: 1, RunID: 2, Sequence: 30, ReportedAt: 1900, Success: true}, {Version: 1, RunID: 2, Sequence: 29, ReportedAt: 1870, Success: false}, {Version: 1, RunID: 2, Sequence: 28, ReportedAt: 1840, Success: true, RecordedRestartBefore: true}}
	pauses, reset := stabilityProgress(samples, p, old)
	if reset != 0 || !reflect.DeepEqual(pauses, []observationPause{{1000, 1840}}) {
		t.Fatal(pauses, reset)
	}
	// A sustained failure remains disqualifying even after it has recovered.
	samples = nil
	for at := int64(1840); at >= 1180; at -= 30 {
		samples = append(samples, DispatchHistorySample{Version: 1, RunID: 2, Sequence: (at-1180)/30 + 11, ReportedAt: at, Success: at == 1840})
	}
	_, reset = stabilityProgress(samples, p, old)
	if reset == 0 {
		t.Fatal("confirmed recovered incident ignored")
	}
	merged := mergeObservationPauses([]observationPause{{100, 200}, {150, 250}, {300, 400}})
	if !reflect.DeepEqual(merged, []observationPause{{100, 250}, {300, 400}}) {
		t.Fatal(merged)
	}
	if stableObserveSeconds != 259200 || whitelistObserveSeconds != 604800 {
		t.Fatal("requires 3 + 7 days")
	}
}

func (f *investigationIntegration) enableLifecycle() {
	f.exec(`UPDATE v2_dispatch_investigation_settings SET lifecycle_enabled=TRUE,lifecycle_started_at=$1`, time.Now().Unix()-11*86400)
}

func (f *investigationIntegration) readyToPromote(g InvestigationGroup, pulled []int64) InvestigationGroup {
	f.execProcess(g.ID)
	task := f.tasks(f.pid)[g.Host]
	yes, latency := true, int64(5)
	var seq int64
	if err := f.db.QueryRow(`SELECT COALESCE(max(sequence),0) FROM v2_dispatch_monitor_state WHERE monitor_id=$1 AND probe_id=$2`, g.MonitorID, f.pid).Scan(&seq); err != nil {
		f.t.Fatal(err)
	}
	for i := int64(1); i <= 2; i++ {
		if _, err := f.s.ReportDispatchProbeResults(f.ctx, f.pid, DNSProbeResultsRequest{Results: []DNSProbeResult{{ResultID: fmt.Sprintf("stable-%d", seq+i), TargetID: task.TargetID, TargetVersion: task.TargetVersion, RunID: task.RunID, Success: &yes, LatencyMS: &latency, ResolvedIP: "203.0.113.222"}}}); err != nil {
			f.t.Fatal(err)
		}
	}
	now := time.Now().Unix()
	required := stableObserveSeconds
	if g.LifecycleRole == "stable" {
		required = whitelistObserveSeconds
	}
	epoch := now - required - 100
	f.exec(`UPDATE v2_dispatch_investigation_settings SET armed_at=$1`, epoch)
	f.exec(`UPDATE v2_dispatch_history SET created_at=$1,payload=jsonb_set(payload,'{reported_at}',to_jsonb($1::bigint)) WHERE source='entry' AND target_id=$2 AND probe_id=$3 AND sequence=$4 AND version=$5 AND run_id=$6`, now-30, g.MonitorID, f.pid, seq+1, task.TargetVersion, task.RunID)
	cp, _ := json.Marshal(map[int64]normalCheckpoint{f.pid: {task.TargetVersion, task.RunID, seq + 1, now - 30}})
	f.exec(`UPDATE v2_dispatch_investigation_group SET epoch_at=$2,ready_at=$2,normal_since=$2,normal_checkpoints=$3 WHERE id=$1`, g.ID, epoch, string(cp))
	g = f.group(g.Host)
	u := usersvc.NewDBService(f.s.cfg, f.db)
	for _, id := range pulled {
		// The fixture advances stages with synthetic dates, not the server
		// clock. Move the preceding host's last receipt before synthetic A.
		f.exec(`UPDATE v2_dispatch_stability_receipt SET last_at=$1 WHERE user_id=$2 AND host<>$3`, epoch, id, g.Host)
		if err := u.RecordInvestigationDelivery(f.ctx, id, []usersvc.InvestigationDelivery{{GroupID: g.ID, Generation: g.Generation, Host: g.Host}}, epoch+1); err != nil {
			f.t.Fatal(err)
		}
	}
	return g
}

func (f *investigationIntegration) stageGroup(role string) InvestigationGroup {
	for _, g := range f.groups() {
		if g.LifecycleRole == role {
			return g
		}
	}
	f.t.Fatal("missing stage", role, f.groups())
	return InvestigationGroup{}
}

func TestPostgresLifecycleTwoStagesPreserveNodeScopeAndReceipts(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.enableLifecycle()
	f.pool("192.0.2.211", "192.0.2.212")
	f.exec(`INSERT INTO v2_server_vmess(id,group_id,name,host,port,server_port,rate,network,"show",created_at,updated_at) VALUES(8,'[1]','other scope','other.example','8443',8443,'1','tcp',1,1,1)`)
	g := f.readyToPromote(f.group("range.example"), []int64{11, 12, 13, 14})
	f.execProcess(g.ID)
	stable := f.stageGroup("stable")
	if stable.RouteScope != "business" || stable.Host == g.Host || stable.Name != "稳定组" || !reflect.DeepEqual(stable.UserIDs, []string{"11", "12", "13", "14"}) {
		t.Fatal(stable)
	}
	// Moving a user is not proof they fetched A. No one can skip stage two.
	f.execProcess(stable.ID)
	for _, x := range f.groups() {
		if x.LifecycleRole == "whitelist" {
			t.Fatal("promoted without fetching A", x)
		}
	}
	stable = f.readyToPromote(stable, []int64{11, 12})
	f.execProcess(stable.ID)
	white := f.stageGroup("whitelist")
	if white.Host == stable.Host || white.Host == g.Host || !reflect.DeepEqual(white.UserIDs, []string{"11", "12"}) {
		t.Fatal(white)
	}
	if !reflect.DeepEqual(f.group(stable.Host).UserIDs, []string{"13", "14"}) {
		t.Fatal("A nonrecipients moved")
	}
	u := usersvc.NewDBService(f.s.cfg, f.db)
	nodes, err := u.Servers(f.ctx, 11, "")
	if err != nil || len(nodes) != 2 {
		t.Fatal(nodes, err)
	}
	if fmt.Sprint(nodes[0]["host"]) != white.Host || fmt.Sprint(nodes[1]["host"]) != "other.example" || fmt.Sprint(nodes[1]["port"]) != "8443" {
		t.Fatal("scope expanded", nodes)
	}
	var globals int
	f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_global_member`).Scan(&globals)
	if globals != 0 {
		t.Fatal("unexpected global override", globals)
	}
	var port int64
	f.db.QueryRow(`SELECT check_port FROM v2_dispatch_monitor WHERE id=$1`, white.MonitorID).Scan(&port)
	if port != 18443 {
		t.Fatal("detection port changed", port)
	}
}

func TestPostgresLifecycleIndividualBoundariesAndSharedEntrance(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.enableLifecycle()
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.readyToPromote(f.group("range.example"), []int64{11, 12, 13, 14})
	now := time.Now().Unix()
	f.exec(`UPDATE v2_dispatch_stability_receipt SET first_at=$1 WHERE user_id IN(13,14)`, now-stableObserveSeconds+100)
	f.execProcess(g.ID)
	stable := f.stageGroup("stable")
	if !reflect.DeepEqual(stable.UserIDs, []string{"11", "12"}) {
		t.Fatal("new users borrowed old time", stable)
	}
	stable = f.readyToPromote(stable, []int64{11, 12})
	// Existing A users' timer survives admitting another eligible batch.
	f.exec(`UPDATE v2_dispatch_stability_receipt SET first_at=$1 WHERE user_id IN(13,14)`, now-stableObserveSeconds-100)
	f.execProcess(g.ID)
	joined := f.group(stable.Host)
	if joined.ID != stable.ID || joined.NormalSince != stable.NormalSince || joined.Generation != stable.Generation || len(joined.UserIDs) != 4 {
		t.Fatal("admission reset established cohort", stable, joined)
	}
	f.execProcess(joined.ID)
	white := f.stageGroup("whitelist")
	if !reflect.DeepEqual(white.UserIDs, []string{"11", "12"}) {
		t.Fatal("new A recipients promoted early", white)
	}
	// Repeated worker execution is idempotent and consumes no third entrance.
	f.execProcess(g.ID)
	var count int
	f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_event WHERE kind='stable_promoted'`).Scan(&count)
	if count != 2 {
		t.Fatal(count)
	}
}

func TestPostgresLifecyclePoolWaitRenameAndSettingsKeepEvidence(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.enableLifecycle()
	g := f.readyToPromote(f.group("range.example"), []int64{11, 12})
	f.execProcess(g.ID)
	for _, x := range f.groups() {
		if x.LifecycleRole == "stable" {
			t.Fatal("allocated without healthy pool")
		}
	}
	before := f.group(g.Host)
	settings, err := readInvestigationSettings(f.ctx, f.db, false)
	if err != nil {
		t.Fatal(err)
	}
	settings.GlobalMax++
	if err = f.s.SaveInvestigation(f.ctx, settings); err != nil {
		t.Fatal(err)
	}
	after := f.group(g.Host)
	if before.Generation != after.Generation || before.NormalSince != after.NormalSince {
		t.Fatal("limits reset evidence")
	}
	if err = f.s.EditInvestigation(f.ctx, InvestigationEdit{ID: after.ID, Revision: after.Revision, Name: "renamed", Host: after.Host, Policy: "smart"}); err != nil {
		t.Fatal(err)
	}
	renamed := f.group(g.Host)
	if renamed.Generation != after.Generation || renamed.NormalSince != after.NormalSince {
		t.Fatal("rename reset evidence")
	}
	f.pool("192.0.2.211")
	f.execProcess(g.ID)
	if !reflect.DeepEqual(f.stageGroup("stable").UserIDs, []string{"11", "12"}) {
		t.Fatal("deferred promotion lost members")
	}
}

func TestPostgresLifecycleSharedStageAcrossBusinessOrigins(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.enableLifecycle()
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.readyToPromote(f.group("range.example"), []int64{11, 12})
	f.execProcess(g.ID)
	stable := f.stageGroup("stable")
	f.readyToPromote(stable, []int64{11, 12})
	before := f.group(stable.Host)
	other := f.readyToPromote(f.group("base.example"), []int64{5, 150})
	f.execProcess(other.ID)
	after := f.stageGroup("stable")
	if after.ID != before.ID || after.Host != before.Host || after.Generation != before.Generation || after.NormalSince != before.NormalSince || !reflect.DeepEqual(after.UserIDs, []string{"5", "11", "12", "150"}) {
		t.Fatal("cross-origin admission changed established evidence", before, after)
	}
	u := usersvc.NewDBService(f.s.cfg, f.db)
	for _, id := range []int64{5, 11, 150} {
		nodes, err := u.Servers(f.ctx, id, "")
		if err != nil || len(nodes) != 1 || fmt.Sprint(nodes[0]["host"]) != after.Host {
			t.Fatal(id, nodes, err)
		}
	}
}

func TestPostgresLifecycleAdmissionAcrossDetectionPorts(t *testing.T) {
	for _, role := range []string{"stable", "whitelist"} {
		t.Run(role, func(t *testing.T) {
			f := newInvestigationIntegration(t)
			f.enableLifecycle()
			f.pool("192.0.2.211", "192.0.2.212")
			root := f.readyToPromote(f.group("range.example"), []int64{11, 12, 13, 14})
			f.execProcess(root.ID)
			target := f.stageGroup("stable")
			if role == "whitelist" {
				target = f.readyToPromote(target, []int64{11, 12, 13, 14})
				f.execProcess(target.ID)
				target = f.stageGroup("whitelist")
			}
			f.exec(`UPDATE v2_dispatch_monitor SET check_port=23135,version=version+1 WHERE id=$1`, target.MonitorID)
			target = f.readyToPromote(f.group(target.Host), []int64{11, 12})
			before := f.group(target.Host)
			source := f.group("base.example")
			if role == "whitelist" {
				f.exec(`UPDATE v2_dispatch_investigation_group SET lifecycle_role='stable' WHERE id=$1`, source.ID)
			}
			f.exec(`UPDATE v2_dispatch_monitor SET check_port=23130,version=version+1 WHERE id=$1`, source.MonitorID)
			source = f.readyToPromote(f.group(source.Host), []int64{5, 150})
			f.execProcess(source.ID)
			after := f.group(target.Host)
			if after.ID != before.ID || after.Generation != before.Generation || after.NormalSince != before.NormalSince || !reflect.DeepEqual(after.NormalCheckpoints, before.NormalCheckpoints) || !reflect.DeepEqual(after.UserIDs, []string{"5", "11", "12", "13", "14", "150"}) {
				t.Fatal("cross-port admission changed target evidence or failed to move members", before, after, f.group(source.Host))
			}
			f.assertCheckPort(source.Host, 23130)
			f.assertCheckPort(target.Host, 23135)
			f.assertUserHosts(5, target.Host)
			f.assertUserHosts(150, target.Host)
			var receipts int
			if err := f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_stability_receipt WHERE user_id IN(5,150) AND host=$1`, target.Host).Scan(&receipts); err != nil || receipts != 0 {
				t.Fatal("admission manufactured destination receipts", receipts, err)
			}
			nodes, err := usersvc.NewDBService(f.s.cfg, f.db).Servers(f.ctx, 5, "")
			if err != nil || len(nodes) != 1 || fmt.Sprint(nodes[0]["port"]) != "443" {
				t.Fatal("detection port overwrote business port", nodes, err)
			}
			f.execProcess(source.ID)
			if !reflect.DeepEqual(f.group(target.Host).UserIDs, after.UserIDs) {
				t.Fatal("repeated admission changed roster")
			}
		})
	}
}

func TestPostgresLifecycleCrossPortUnhealthyStageStillBlocksAdmission(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.enableLifecycle()
	f.pool("192.0.2.211")
	root := f.readyToPromote(f.group("range.example"), []int64{11, 12})
	f.execProcess(root.ID)
	target := f.stageGroup("stable")
	f.exec(`UPDATE v2_dispatch_monitor SET check_port=23135,version=version+1 WHERE id=$1`, target.MonitorID)
	f.readyToPromote(f.group(target.Host), []int64{11, 12})
	source := f.readyToPromote(f.group("base.example"), []int64{5, 150})
	f.timeout(target.Host)
	before := f.snapshot("v2_dispatch_investigation_member")
	f.execProcess(source.ID)
	if !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_member")) || f.group(source.Host).Reason != "阶段入口异常，暂停接收新成员" {
		t.Fatal("unhealthy cross-port stage accepted recipients", f.groups())
	}
}

func TestPostgresLifecycleSingleFixedAndDisabledNeverPromote(t *testing.T) {
	for _, mode := range []string{"fixed", "single", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			f := newInvestigationIntegration(t)
			f.enableLifecycle()
			f.pool("192.0.2.211")
			g := f.readyToPromote(f.group("range.example"), []int64{11, 12})
			switch mode {
			case "fixed":
				f.exec(`UPDATE v2_dispatch_investigation_group SET policy='fixed' WHERE id=$1`, g.ID)
			case "single":
				f.exec(`DELETE FROM v2_user WHERE id IN(12,13,14,15,16,17,42)`)
			case "disabled":
				f.exec(`UPDATE v2_dispatch_investigation_settings SET lifecycle_enabled=FALSE`)
			}
			f.execProcess(g.ID)
			for _, x := range f.groups() {
				if x.LifecycleRole == "stable" {
					t.Fatal("protected source promoted", x)
				}
			}
		})
	}
}

func TestPostgresLifecyclePromotionRejectsNewFailure(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.enableLifecycle()
	g := f.readyToPromote(f.group("range.example"), []int64{11, 12})
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.verifyPromotionObservation(f.ctx, tx, g); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	tx.Rollback()
	f.timeout(g.Host)
	tx, err = f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = f.s.verifyPromotionObservation(f.ctx, tx, g); err == nil {
		t.Fatal("late failure accepted")
	}
}

func TestPostgresLifecycleSevenDaysStartsAtActualAReceipt(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.enableLifecycle()
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.readyToPromote(f.group("range.example"), []int64{11, 12})
	f.execProcess(g.ID)
	stable := f.readyToPromote(f.stageGroup("stable"), []int64{11, 12})
	var end int64
	f.db.QueryRow(`SELECT reported_at FROM v2_dispatch_monitor_state WHERE monitor_id=$1 AND probe_id=$2`, stable.MonitorID, f.pid).Scan(&end)
	f.exec(`UPDATE v2_dispatch_stability_receipt SET first_at=$1 WHERE host=$2`, end-whitelistObserveSeconds+1, stable.Host)
	f.execProcess(stable.ID)
	for _, x := range f.groups() {
		if x.LifecycleRole == "whitelist" {
			t.Fatal("promoted before full seven days", x)
		}
	}
	f.exec(`UPDATE v2_dispatch_stability_receipt SET first_at=$1 WHERE host=$2`, end-whitelistObserveSeconds, stable.Host)
	f.execProcess(stable.ID)
	if !reflect.DeepEqual(f.stageGroup("whitelist").UserIDs, []string{"11", "12"}) {
		t.Fatal("seven-day boundary did not promote")
	}
}

func TestPostgresLifecycleAllocationRollbackIsAtomic(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.enableLifecycle()
	f.pool("192.0.2.211")
	g := f.readyToPromote(f.group("range.example"), []int64{11, 12})
	f.exec(`ALTER TABLE v2_dispatch_investigation_member ADD CONSTRAINT lifecycle_test_reject_move CHECK(group_id<>3)`)
	f.execProcess(g.ID)
	if !reflect.DeepEqual(f.group(g.Host).UserIDs, g.UserIDs) {
		t.Fatal("partial membership migration")
	}
	var stages, monitors, audits int
	f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_group WHERE lifecycle_role='stable'`).Scan(&stages)
	f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_monitor WHERE host='192.0.2.211'`).Scan(&monitors)
	f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_event WHERE kind='stable_promoted'`).Scan(&audits)
	if stages != 0 || monitors != 0 || audits != 0 {
		t.Fatal("allocation leaked after failed member write", stages, monitors, audits)
	}
	f.exec(`ALTER TABLE v2_dispatch_investigation_member DROP CONSTRAINT lifecycle_test_reject_move`)
	f.execProcess(g.ID)
	if len(f.stageGroup("stable").UserIDs) != 2 {
		t.Fatal("rolled back IP could not be reused")
	}
}

func TestPostgresLifecycleSameHostRoundPreservesIndividualEvidence(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.enableLifecycle()
	f.pool("192.0.2.211")
	g := f.readyToPromote(f.group("range.example"), []int64{11, 12})
	// A same-host merge changes receipt round but not endpoint ownership.
	f.exec(`UPDATE v2_dispatch_investigation_group SET generation=generation+1,epoch_at=$2 WHERE id=$1`, g.ID, time.Now().Unix()-1)
	f.execProcess(g.ID)
	if !reflect.DeepEqual(f.stageGroup("stable").UserIDs, []string{"11", "12"}) {
		t.Fatal("same-host round lost valid individual evidence")
	}
}

func TestPostgresLifecycleRestartKeepsEarnedObservation(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.enableLifecycle()
	f.pool("192.0.2.211")
	g := f.readyToPromote(f.group("range.example"), []int64{11, 12})
	// A healthy but not-yet-mature source survives the actual startup reset.
	start := time.Now().Unix() - 2*86400
	f.exec(`UPDATE v2_dispatch_investigation_group SET normal_since=$2 WHERE id=$1`, g.ID, start)
	f.restartWithEvidence()
	task := f.tasks(f.pid)[g.Host]
	yes, latency := true, int64(5)
	if _, err := f.s.ReportDispatchProbeResults(f.ctx, f.pid, DNSProbeResultsRequest{Results: []DNSProbeResult{{ResultID: "restart-stability-1", TargetID: task.TargetID, TargetVersion: task.TargetVersion, RunID: task.RunID, Success: &yes, LatencyMS: &latency}}}); err != nil {
		t.Fatal(err)
	}
	f.execProcess(g.ID)
	after := f.group(g.Host)
	if after.Generation != g.Generation || after.NormalSince < start || after.NormalSince > start+60 {
		t.Fatal("restart erased earned time", g, after)
	}
}

func TestPostgresLifecycleWhitelistTwoFaultsAndSideInvestigation(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.enableLifecycle()
	f.pool("192.0.2.211", "192.0.2.212", "192.0.2.213", "192.0.2.214", "192.0.2.215")
	g := f.readyToPromote(f.group("range.example"), []int64{11, 12, 13, 14})
	f.execProcess(g.ID)
	stable := f.readyToPromote(f.stageGroup("stable"), []int64{11, 12, 13, 14})
	f.execProcess(stable.ID)
	white := f.stageGroup("whitelist")
	oldHost := white.Host
	f.outage(white, []int64{11, 12, 13, 14})
	f.execProcess(white.ID)
	white = f.stageGroup("whitelist")
	if white.Host == oldHost || len(white.UserIDs) != 4 {
		t.Fatal("first fault did not fail over", white)
	}
	f.exec(`UPDATE v2_dispatch_investigation_event SET created_at=created_at-1300 WHERE kind='whitelist_failed_over'`)
	f.outage(white, []int64{11, 12, 13, 14})
	f.execProcess(white.ID)
	children := []InvestigationGroup{}
	for _, x := range f.groups() {
		if x.ParentID == white.ID {
			children = append(children, x)
		}
	}
	if len(children) != 2 || children[0].Host == children[1].Host {
		t.Fatal("second fault did not bisect", f.groups())
	}
	for _, x := range children {
		if x.LifecycleRole != "review" || x.RouteScope != "business" || len(x.UserIDs) != 2 {
			t.Fatal(x)
		}
	}
}

func TestPostgresLifecycleReceiptFailureOnlyRecovers(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.enableLifecycle()
	f.pool("192.0.2.211")
	g := f.group("range.example")
	f.outage(g, []int64{11, 12})
	f.exec(`UPDATE v2_dispatch_investigation_health SET delivery_failure_at=$1 WHERE id=1`, time.Now().Unix())
	f.execProcess(g.ID)
	after := f.group("192.0.2.211")
	if after.ID != g.ID || !reflect.DeepEqual(after.UserIDs, g.UserIDs) {
		t.Fatal("missing evidence used to screen", after)
	}
}
