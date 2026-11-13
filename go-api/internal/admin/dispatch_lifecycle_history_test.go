package admin

import (
	"encoding/json"
	"testing"
	"time"
)

func (f *investigationIntegration) legacyObservation(hours int64, gap bool) InvestigationGroup {
	g := f.group("range.example")
	f.execProcess(g.ID)
	task := f.tasks(f.pid)[g.Host]
	yes, latency := true, int64(5)
	if _, err := f.s.ReportDispatchProbeResults(f.ctx, f.pid, DNSProbeResultsRequest{Results: []DNSProbeResult{{ResultID: "legacy-1", TargetID: task.TargetID, TargetVersion: task.TargetVersion, RunID: task.RunID, Success: &yes, LatencyMS: &latency}}}); err != nil {
		f.t.Fatal(err)
	}
	now := time.Now().Unix()
	start := now - hours*3600
	f.exec(`DELETE FROM v2_dispatch_history WHERE source='entry' AND target_id=$1`, g.MonitorID)
	for seq, at := int64(1), start; at <= now; seq, at = seq+1, at+30 {
		if gap && at >= start+600 && at < start+1200 {
			continue
		}
		x := DispatchHistorySample{Source: "entry", TargetID: g.MonitorID, ProbeID: f.pid, Version: task.TargetVersion, RunID: task.RunID, Sequence: seq, Success: true, ReportedAt: at, Host: g.Host, Port: 18443}
		raw, _ := json.Marshal(x)
		f.exec(`INSERT INTO v2_dispatch_history(source,target_id,probe_id,version,run_id,sequence,kind,host,port,success,payload,created_at) VALUES('entry',$1,$2,$3,$4,$5,'sample',$6,18443,TRUE,$7,$8)`, g.MonitorID, f.pid, x.Version, x.RunID, seq, g.Host, string(raw), at)
	}
	f.exec(`UPDATE v2_dispatch_monitor_state SET success=TRUE,reported_at=$1,sequence=$2 WHERE monitor_id=$3 AND probe_id=$4`, now, hours*120+1, g.MonitorID, f.pid)
	f.exec(`UPDATE v2_dispatch_investigation_settings SET armed_at=$1,lifecycle_enabled=FALSE,lifecycle_started_at=0`, start-86400)
	f.exec(`UPDATE v2_dispatch_investigation_group SET epoch_at=$2,ready_at=$2,created_at=$2,normal_since=0,normal_checkpoints='{}',normal_history_imported=FALSE WHERE id=$1`, g.ID, start)
	f.exec(`DELETE FROM v2_dispatch_stability_receipt`)
	// Two genuine current-round recipients; an old-generation receipt and an
	// unassigned user must never become promotion candidates.
	for _, id := range []int64{11, 12} {
		f.exec(`INSERT INTO v2_dispatch_investigation_delivery VALUES($1,$2,$3,$4)`, g.ID, g.Generation, id, start+30)
	}
	f.exec(`INSERT INTO v2_dispatch_investigation_delivery VALUES($1,$2,13,$3),($1,$4,999999,$3)`, g.ID, g.Generation-1, start-3600, g.Generation)
	return f.group(g.Host)
}

func TestPostgresLifecycleHistoryImportDisabledAndResume(t *testing.T) {
	f := newInvestigationIntegration(t)
	g := f.legacyObservation(1, true)
	f.execProcess(g.ID)
	after := f.group(g.Host)
	elapsed := after.NormalObservedAt - after.NormalSince
	if !after.NormalHistoryImported || elapsed != 3600 || after.Generation != g.Generation || after.EpochAt != g.EpochAt {
		t.Fatal("unchanged historical round was not credited", elapsed, after)
	}
	var users int
	f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_stability_receipt WHERE host=$1`, g.Host).Scan(&users)
	if users != 2 {
		t.Fatal("wrong current-round recipients", users)
	}
	settings, err := readInvestigationSettings(f.ctx, f.db, false)
	if err != nil {
		t.Fatal(err)
	}
	settings.LifecycleEnabled = true
	if err = f.s.SaveInvestigation(f.ctx, settings); err != nil {
		t.Fatal(err)
	}
	f.execProcess(g.ID)
	enabled := f.group(g.Host)
	if enabled.NormalSince != after.NormalSince || enabled.Generation != after.Generation {
		t.Fatal("enable reset imported observation", after, enabled)
	}
	f.execProcess(g.ID)
	var count int
	f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_event WHERE group_id=$1 AND kind='observation_imported'`, g.ID).Scan(&count)
	if count != 1 {
		t.Fatal("import replayed", count)
	}
}

func TestPostgresLifecycleHistoryImportCanPromoteWithoutWaitingAgain(t *testing.T) {
	f := newInvestigationIntegration(t)
	g := f.legacyObservation(73, false)
	// Production only retains one day of raw samples. The other two days
	// still count under the explicit unchanged-round business policy.
	f.exec(`DELETE FROM v2_dispatch_history WHERE source='entry' AND target_id=$1 AND created_at<$2`, g.MonitorID, time.Now().Unix()-86400)
	f.pool("192.0.2.211")
	f.execProcess(g.ID)
	settings, err := readInvestigationSettings(f.ctx, f.db, false)
	if err != nil {
		t.Fatal(err)
	}
	settings.LifecycleEnabled = true
	if err = f.s.SaveInvestigation(f.ctx, settings); err != nil {
		t.Fatal(err)
	}
	f.execProcess(g.ID)
	stable := f.stageGroup("stable")
	if len(stable.UserIDs) != 2 || stable.UserIDs[0] != "11" || stable.UserIDs[1] != "12" {
		t.Fatal(stable)
	}
	f.execProcess(stable.ID)
	for _, x := range f.groups() {
		if x.LifecycleRole == "whitelist" {
			t.Fatal("old evidence skipped A's seven days", x)
		}
	}
}

func TestPostgresLifecycleHistoryLiveConfirmedFaultStillResets(t *testing.T) {
	f := newInvestigationIntegration(t)
	g := f.legacyObservation(1, false)
	f.execProcess(g.ID)
	task := f.tasks(f.pid)[g.Host]
	cp, _ := json.Marshal(map[int64]normalCheckpoint{f.pid: {task.TargetVersion, task.RunID, 1, g.EpochAt}})
	f.exec(`UPDATE v2_dispatch_investigation_group SET normal_checkpoints=$2 WHERE id=$1`, g.ID, string(cp))
	f.exec(`UPDATE v2_dispatch_history SET success=FALSE,payload=jsonb_set(payload,'{success}','false') WHERE source='entry' AND target_id=$1 AND sequence BETWEEN 20 AND 42`, g.MonitorID)
	f.execProcess(g.ID)
	after := f.group(g.Host)
	if after.NormalObservedAt-after.NormalSince > 30 {
		t.Fatal("pre-fault health was credited after confirmed failure", after)
	}
}

func TestPostgresLifecycleHistoryRestartAndExistingCheckpoint(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy_restart", true: "existing_progress"}[existing], func(t *testing.T) {
			f := newInvestigationIntegration(t)
			g := f.legacyObservation(1, false)
			if existing {
				f.execProcess(g.ID)
				f.exec(`UPDATE v2_dispatch_investigation_group SET normal_since=$2,normal_history_imported=FALSE WHERE id=$1`, g.ID, time.Now().Unix()-2*86400)
			}
			f.restartWithEvidence()
			f.execProcess(g.ID)
			after := f.group(g.Host)
			minimum := int64(3500)
			if existing {
				minimum = 2*86400 - 100
			}
			if after.Generation != g.Generation || after.NormalObservedAt-after.NormalSince < minimum {
				t.Fatal("upgrade restart lost verified history", existing, after)
			}
		})
	}
}

func TestLifecycleHistoryBoundaryUsesLatestActionOrRound(t *testing.T) {
	g := InvestigationGroup{EpochAt: 100}
	s := InvestigationSettings{ArmedAt: 90}
	if got := legacyObservationStart(g, s, 80, 95); got != 100 {
		t.Fatal(got)
	}
	if got := legacyObservationStart(g, s, 80, 120); got != 120 {
		t.Fatal(got)
	}
	if got := legacyObservationStart(g, s, 130, 120); got != 130 {
		t.Fatal(got)
	}
}

func TestPostgresLifecycleHistoryManualEditAndScreeningBoundaries(t *testing.T) {
	for _, kind := range []string{"edited", "filtered", "bisected", "no_pulls", "recovered", "confirmed_entry", "members_moved"} {
		t.Run(kind, func(t *testing.T) {
			f := newInvestigationIntegration(t)
			g := f.legacyObservation(1, false)
			boundary := time.Now().Unix() - 600
			f.exec(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload) VALUES($1,$1,$2,$3,'{}')`, g.ID, kind, boundary)
			f.exec(`INSERT INTO v2_dispatch_investigation_delivery_recent VALUES($1,$2,12,$3)`, g.ID, g.Generation, boundary+30)
			f.exec(`INSERT INTO v2_dispatch_stability_receipt(origin_host,user_id,host,first_at,last_at) SELECT origin_host,user_id,$2,$3,$3 FROM v2_dispatch_investigation_member WHERE group_id=$1 AND user_id IN(11,12)`, g.ID, g.Host, boundary-100)
			f.execProcess(g.ID)
			after := f.group(g.Host)
			if after.NormalSince != boundary {
				t.Fatal("action boundary ignored", after)
			}
			var ids string
			if err := f.db.QueryRow(`SELECT COALESCE(string_agg(user_id::text,',' ORDER BY user_id),'') FROM v2_dispatch_stability_receipt WHERE host=$1`, g.Host).Scan(&ids); err != nil || ids != "12" {
				t.Fatal("old recipients crossed action boundary", ids, err)
			}
			var first int64
			if err := f.db.QueryRow(`SELECT first_at FROM v2_dispatch_stability_receipt WHERE host=$1 AND user_id=12`, g.Host).Scan(&first); err != nil || first != boundary+30 {
				t.Fatal("receipt before manual edit leaked into timer", first, err)
			}
		})
	}
}
