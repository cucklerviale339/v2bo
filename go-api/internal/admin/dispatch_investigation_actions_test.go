package admin

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	usersvc "forest/go-api/internal/user"
)

func TestInvestigationConfirmedBaselineAndImmediateDuration(t *testing.T) {
	c, samples := timestampEvidence(false)
	epoch := samples[len(samples)-1].ReportedAt
	if _, ok := investigationTimeoutStart(samples, c, c.Reported, epoch); ok {
		t.Fatal("unknown start accepted without confirmation")
	}
	if first, ok := investigationTimeoutStartAfterConfirmation(samples, c, c.Reported, epoch, epoch, 600); !ok || first != epoch {
		t.Fatal("confirmed continuous outage rejected", first, ok)
	}
	for _, name := range []string{"gap", "other_error", "old_round", "late_start", "version", "session"} {
		t.Run(name, func(t *testing.T) {
			v := append([]DispatchHistorySample{}, samples...)
			confirmed := epoch
			switch name {
			case "gap":
				v[8].Sequence -= int64(50 * time.Second)
			case "other_error":
				v[8].Error = "dns_error"
			case "old_round":
				confirmed--
			case "late_start":
				v = v[:len(v)-3]
			case "version":
				v[8].Version++
			case "session":
				v[8].RunID++
			}
			if _, ok := investigationTimeoutStartAfterConfirmation(v, c, c.Reported, epoch, confirmed, 0); ok {
				t.Fatal("unsafe manual evidence accepted")
			}
		})
	}
	short := append([]DispatchHistorySample{}, samples[:3]...)
	short[2].Success = true
	if _, ok := investigationTimeoutStartAfterConfirmation(short, c, c.Reported, epoch, 0, 600); ok {
		t.Fatal("automatic action skipped ten minutes")
	}
	if _, ok := investigationTimeoutStartAfterConfirmation(short, c, c.Reported, epoch, 0, 0); !ok {
		t.Fatal("manual trigger did not skip duration")
	}
	short[2].Success = false
	if _, ok := investigationTimeoutStartAfterConfirmation(short, c, c.Reported, epoch, 0, 0); ok {
		t.Fatal("manual trigger accepted unknown start")
	}
}

func (f *investigationIntegration) restartWithEvidence() {
	f.t.Helper()
	f.timestampHistory()
	f.exec(`CREATE TEMP TABLE restart_states AS TABLE v2_dispatch_monitor_state`)
	f.s.dispatchSchemaOK = false
	if err := f.s.ensureDispatchMonitorSchema(f.ctx); err != nil {
		f.t.Fatal(err)
	}
	// Fresh observations arrive in the new run. Move the last two fixture
	// observations rather than replaying an old report through the API.
	f.exec(`WITH recent AS (SELECT id FROM (SELECT id,row_number() OVER(PARTITION BY target_id,probe_id ORDER BY created_at DESC,id DESC) n FROM v2_dispatch_history WHERE source='entry' AND kind='sample') x WHERE n<=2) UPDATE v2_dispatch_history SET run_id=run_id+1,payload=jsonb_set(payload,'{run_id}',to_jsonb(run_id+1)) WHERE id IN(SELECT id FROM recent)`)
	f.exec(`INSERT INTO v2_dispatch_monitor_state SELECT * FROM restart_states`)
	tasks, err := f.s.ListDispatchCheckTasks(f.ctx, f.pid)
	if err != nil {
		f.t.Fatal(err)
	}
	yes, latency := true, int64(5)
	for _, task := range tasks {
		for _, resultID := range []string{"restart-1", "restart-2"} {
			if _, err := f.s.ReportDispatchCheckResults(f.ctx, f.pid, DNSProbeResultsRequest{Results: []DNSProbeResult{{ResultID: resultID, TargetID: task.TargetID, TargetVersion: task.TargetVersion, RunID: task.RunID, Success: &yes, LatencyMS: &latency}}}); err != nil {
				f.t.Fatal(err)
			}
		}
	}
}

func TestPostgresInvestigationRestartPreservesRoundAndContinuousEvidence(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.group("range.example")
	f.outage(g, []int64{11, 12, 13})
	g = f.group(g.Host)
	f.restartWithEvidence()
	f.execProcess(g.ID)
	if f.successfulEvents() != 1 {
		t.Fatal("restart lost continuous incident", f.groups())
	}
	var generation, epoch int64
	f.db.QueryRow(`SELECT generation,epoch_at FROM v2_dispatch_investigation_group WHERE id=$1`, g.ID).Scan(&generation, &epoch)
	if generation != g.Generation || epoch != g.EpochAt {
		t.Fatal("restart discarded receipt generation", generation, epoch, g)
	}
	for _, child := range f.groups() {
		if child.ParentID == g.ID {
			f.assertCheckPort(child.Host, 18443)
		}
	}
}

func TestPostgresInvestigationRestartGapAndReconnectDoNotTrigger(t *testing.T) {
	for _, kind := range []string{"gap", "reconnect", "port"} {
		t.Run(kind, func(t *testing.T) {
			f := newInvestigationIntegration(t)
			f.pool("192.0.2.211", "192.0.2.212")
			g := f.group("range.example")
			f.outage(g, []int64{11, 12})
			g = f.group(g.Host)
			if kind == "reconnect" {
				f.exec(`UPDATE v2_dispatch_monitor_probe SET run_id=run_id+1 WHERE monitor_id=$1`, g.MonitorID)
			} else {
				f.restartWithEvidence()
				if kind == "gap" {
					f.exec(`UPDATE v2_dispatch_history SET created_at=created_at-120,payload=jsonb_set(payload,'{reported_at}',to_jsonb(created_at-120)) WHERE source='entry' AND target_id=$1 AND run_id=(SELECT min(run_id) FROM v2_dispatch_history WHERE source='entry' AND target_id=$1)`, g.MonitorID)
				} else {
					f.exec(`UPDATE v2_dispatch_monitor SET check_port=18444,version=version+1 WHERE id=$1`, g.MonitorID)
				}
			}
			f.execProcess(g.ID)
			if f.successfulEvents() != 0 {
				t.Fatal("unsafe restart triggered", f.groups())
			}
			if kind != "gap" && f.group(g.Host).ReadyAt != 0 {
				t.Fatal("configuration/reconnect failed to reset")
			}
		})
	}
}

func TestPostgresInvestigationRestartMissingStateRetainsRound(t *testing.T) {
	f := newInvestigationIntegration(t)
	g := f.group("range.example")
	f.outage(g, nil)
	g = f.group(g.Host)
	f.s.dispatchSchemaOK = false
	if err := f.s.ensureDispatchMonitorSchema(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.execProcess(g.ID)
	next := f.group(g.Host)
	if next.ReadyAt != g.ReadyAt || next.EpochAt != g.EpochAt || next.Generation != g.Generation || f.successfulEvents() != 0 {
		t.Fatal("startup without fresh reports erased round", g, next)
	}
}

func TestPostgresInvestigationManualTriggerShortOutageAndIdempotency(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.group("range.example")
	f.outage(g, []int64{11, 12, 13})
	// Compress the target's complete incident to under ten minutes. Controls
	// retain their full healthy span and the preceding success is preserved.
	var reported int64
	if err := f.db.QueryRow(`SELECT reported_at FROM v2_dispatch_monitor_state WHERE monitor_id=$1 AND probe_id=$2`, g.MonitorID, f.pid).Scan(&reported); err != nil {
		t.Fatal(err)
	}
	f.exec(`UPDATE v2_dispatch_history SET created_at=$2-(22-sequence)*3,payload=jsonb_set(payload,'{reported_at}',to_jsonb($2::bigint-(22-sequence)*3)) WHERE source='entry' AND target_id=$1`, g.MonitorID, reported)
	f.execProcess(g.ID)
	if f.successfulEvents() != 0 {
		t.Fatal("automatic path skipped duration")
	}
	g = f.group(g.Host)
	action := InvestigationAction{ID: g.ID, Revision: g.Revision}
	if err := f.s.TriggerInvestigation(f.ctx, action); err != nil {
		t.Fatal(err, f.groups())
	}
	if f.successfulEvents() != 1 {
		t.Fatal("manual short incident did not apply", f.groups())
	}
	if err := f.s.TriggerInvestigation(f.ctx, action); err == nil || f.successfulEvents() != 1 {
		t.Fatal("repeated manual trigger succeeded", err)
	}
	var audits int
	f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_event WHERE kind='manual_trigger'`).Scan(&audits)
	if audits != 1 {
		t.Fatal("manual trigger missing audit", audits)
	}
}

func TestPostgresInvestigationManualTriggerRetainsGuards(t *testing.T) {
	for _, kind := range []string{"unknown_start", "control", "pool", "cooldown", "global", "disabled", "single", "revision", "deleted", "scope"} {
		t.Run(kind, func(t *testing.T) {
			f := newInvestigationIntegration(t)
			f.pool("192.0.2.211", "192.0.2.212")
			g := f.group("range.example")
			f.outage(g, []int64{11, 12, 13})
			g = f.group(g.Host)
			switch kind {
			case "unknown_start":
				f.exec(`UPDATE v2_dispatch_history SET success=FALSE,payload=jsonb_set(jsonb_set(payload,'{success}','false'::jsonb),'{error}','"timeout"'::jsonb) WHERE source='entry' AND target_id=$1`, g.MonitorID)
			case "control":
				f.exec(`UPDATE v2_dispatch_monitor_state SET success=FALSE WHERE monitor_id<>$1`, g.MonitorID)
			case "pool":
				f.exec(`UPDATE v2_dispatch_check_target SET enabled=FALSE WHERE kind='pool'`)
			case "cooldown":
				f.exec(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload) VALUES($1,$1,'filtered',$2,'{}')`, g.RootID, time.Now().Unix())
			case "global":
				f.exec(`UPDATE v2_dispatch_investigation_settings SET global_max=1`)
				f.exec(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload) VALUES(999,999,'filtered',$1,'{}')`, time.Now().Unix())
			case "disabled":
				f.exec(`UPDATE v2_dispatch_investigation_settings SET enabled=FALSE`)
			case "single":
				f.exec(`DELETE FROM v2_dispatch_investigation_member WHERE group_id=$1 AND user_id<>11`, g.ID)
			case "revision":
				g.Revision--
			case "deleted":
				f.exec(`UPDATE v2_dispatch_monitor SET deleted=TRUE WHERE id=$1`, g.MonitorID)
			case "scope":
				f.exec(`UPDATE v2_dispatch_investigation_settings SET scope='multi_range'`)
			}
			before := f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_monitor", "v2_dispatch_investigation_event")
			if err := f.s.TriggerInvestigation(f.ctx, InvestigationAction{ID: g.ID, Revision: g.Revision}); err == nil {
				t.Fatal("guard bypassed", kind)
			}
			// Deleted-monitor exclusion is intentionally applied by ensure.
			if kind != "deleted" && !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_monitor", "v2_dispatch_investigation_event")) {
				t.Fatal("failed action partially committed", kind)
			}
		})
	}
}

func TestPostgresInvestigationConfirmationNewRoundAndGuards(t *testing.T) {
	f := newInvestigationIntegration(t)
	g := f.group("range.example")
	f.outage(g, []int64{11})
	g = f.group(g.Host)
	before := f.snapshot("v2_dispatch_investigation_member", "v2_dispatch_monitor")
	action := InvestigationAction{ID: g.ID, Revision: g.Revision}
	if err := f.s.ConfirmInvestigation(f.ctx, action); err != nil {
		t.Fatal(err)
	}
	next := f.group(g.Host)
	if next.Generation != g.Generation+1 || next.ConfirmedAt != next.EpochAt || next.ReadyAt != next.EpochAt || next.Revision != g.Revision+1 || !reflect.DeepEqual(next.UserIDs, g.UserIDs) || !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_member", "v2_dispatch_monitor")) {
		t.Fatal("confirmation altered assignment or failed baseline", next)
	}
	if err := f.s.ConfirmInvestigation(f.ctx, action); err == nil {
		t.Fatal("duplicate confirmation accepted")
	}
	if err := f.s.TriggerInvestigation(f.ctx, InvestigationAction{ID: next.ID, Revision: next.Revision}); err == nil || !strings.Contains(err.Error(), "故障起点") {
		t.Fatal("confirmation borrowed pre-click outage", err)
	}
	for _, kind := range []string{"single", "manual", "disabled", "deleted", "offline", "scope"} {
		t.Run(kind, func(t *testing.T) {
			f := newInvestigationIntegration(t)
			g := f.group("range.example")
			f.outage(g, nil)
			g = f.group(g.Host)
			switch kind {
			case "single":
				f.exec(`DELETE FROM v2_dispatch_investigation_member WHERE group_id=$1 AND user_id<>11`, g.ID)
			case "manual":
				f.exec(`UPDATE v2_dispatch_investigation_group SET manual_only=TRUE WHERE id=$1`, g.ID)
			case "disabled":
				f.exec(`UPDATE v2_dispatch_investigation_settings SET enabled=FALSE`)
			case "deleted":
				f.exec(`UPDATE v2_dispatch_monitor SET deleted=TRUE WHERE id=$1`, g.MonitorID)
			case "offline":
				f.exec(`UPDATE v2_dns_probe SET last_heartbeat_at=0`)
			case "scope":
				f.exec(`UPDATE v2_dispatch_investigation_settings SET scope='multi_range'`)
			}
			if err := f.s.ConfirmInvestigation(f.ctx, InvestigationAction{ID: g.ID, Revision: g.Revision}); err == nil {
				t.Fatal("confirmation guard bypassed", kind)
			}
		})
	}
}

func TestPostgresInvestigationConfirmedFailingEntryCanFilter(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.group("range.example")
	f.outage(g, []int64{42}) // Old-generation pull must not enter the new round.
	g = f.group(g.Host)
	if err := f.s.ConfirmInvestigation(f.ctx, InvestigationAction{ID: g.ID, Revision: g.Revision}); err != nil {
		t.Fatal(err)
	}
	at := time.Now().Unix() - 650
	f.exec(`UPDATE v2_dispatch_investigation_group SET epoch_at=$2,ready_at=$2 WHERE id=$1`, g.ID, at)
	f.exec(`UPDATE v2_dispatch_investigation_confirmation SET confirmed_at=$2 WHERE group_id=$1`, g.ID, at)
	// Model ten minutes after the confirmation: every target result times out,
	// with the first received check 20s after the explicit baseline.
	f.exec(`UPDATE v2_dispatch_history SET success=FALSE,payload=jsonb_set(jsonb_set(payload,'{success}','false'::jsonb),'{error}','"timeout"'::jsonb) WHERE source='entry' AND target_id=$1`, g.MonitorID)
	g = f.group(g.Host)
	for _, id := range []int64{11, 12, 13} {
		if err := usersvc.NewDBService(f.s.cfg, f.db).RecordInvestigationDelivery(f.ctx, id, []usersvc.InvestigationDelivery{{GroupID: g.ID, Generation: g.Generation, Host: g.Host}}, at+5); err != nil {
			t.Fatal(err)
		}
	}
	f.execProcess(g.ID)
	if f.successfulEvents() != 1 {
		t.Fatal("confirmed failed entry remained blocked", f.groups())
	}
	for _, child := range f.groups() {
		if child.ParentID == g.ID && child.Kind == "recent" && !reflect.DeepEqual(child.UserIDs, []string{"11", "12", "13"}) {
			t.Fatal("old-round receipt contaminated partition", child)
		}
	}
}

func TestPostgresInvestigationConcurrentManualTriggerConsumesOnce(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.group("range.example")
	f.outage(g, []int64{11, 12, 13})
	g = f.group(g.Host)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- f.s.TriggerInvestigation(f.ctx, InvestigationAction{ID: g.ID, Revision: g.Revision})
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	success := 0
	for err := range errs {
		if err == nil {
			success++
		}
	}
	if success != 1 || f.successfulEvents() != 1 {
		t.Fatal("concurrent trigger duplicated or lost operation", success, f.groups())
	}
}

func TestPostgresInvestigationManualTriggerRollsBackChangedCutoff(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.group("range.example")
	f.outage(g, []int64{11, 12, 13})
	g = f.group(g.Host)
	// Simulate a recovery becoming visible after partitioning but before the
	// final evidence check. The new cutoff must not commit the old partition.
	f.exec(`CREATE FUNCTION change_fault_cutoff() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE v2_dispatch_history SET success=TRUE,payload=jsonb_set(jsonb_set(payload,'{success}','true'::jsonb),'{error}','""'::jsonb) WHERE source='entry' AND kind='sample' AND host='range.example' AND sequence=11; RETURN NEW; END $$`)
	f.exec(`CREATE TRIGGER change_fault_cutoff BEFORE INSERT ON v2_dispatch_monitor FOR EACH ROW EXECUTE FUNCTION change_fault_cutoff()`)
	before := f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_monitor", "v2_dispatch_investigation_event", "v2_dispatch_history")
	err := f.s.TriggerInvestigation(f.ctx, InvestigationAction{ID: g.ID, Revision: g.Revision})
	if err == nil || !strings.Contains(err.Error(), "故障起点发生变化") {
		t.Fatal("cutoff change did not abort", err)
	}
	if !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_monitor", "v2_dispatch_investigation_event", "v2_dispatch_history")) {
		t.Fatal("changed cutoff partially committed")
	}
}

func TestPostgresInvestigationCorrectedPortUsesLatestHealthyState(t *testing.T) {
	f := newInvestigationIntegration(t)
	g := f.group("range.example")
	savePort := func(port int64) {
		t.Helper()
		if err := f.s.SaveDispatchMonitor(f.ctx, DispatchMonitorSaveRequest{Host: g.Host, CheckPort: port, Enabled: true, CheckIntervalSec: 30, TCPTimeoutMS: 500, ProbeIDs: []int64{f.pid}}); err != nil {
			t.Fatal(err)
		}
	}
	savePort(443)
	f.timeout(g.Host)
	f.execProcess(g.ID)
	wrongTask := f.tasks(f.pid)[g.Host]
	before := f.snapshot("v2_dispatch_investigation_member", "v2_node_address_rule", "v2_insider_rule")
	savePort(18443)
	f.execProcess(g.ID) // Observe the configuration change before new results.
	if current := f.group(g.Host); current.ReadyAt != 0 || current.MonitorID != g.MonitorID {
		t.Fatal("changed port reused old readiness or monitor identity", current)
	}
	// A late result for the wrong port must not revive the new configuration.
	f.report(f.pid, wrongTask, 23, 0, 1)
	correctTask := f.tasks(f.pid)[g.Host]
	if correctTask.CheckPort != 18443 || correctTask.TargetVersion == wrongTask.TargetVersion {
		t.Fatal("probe task did not switch to corrected port", correctTask)
	}
	f.report(f.pid, correctTask, 1, 1, 0)
	f.execProcess(g.ID)
	current := f.group(g.Host)
	monitor := f.monitors(false)[g.Host]
	if current.MonitorID != g.MonitorID || current.ReadyAt == 0 || current.Reason != "正常观察中" || monitor.CheckPort != 18443 || len(monitor.States) != 1 || monitor.States[0].Stale || monitor.States[0].Success == nil || !*monitor.States[0].Success {
		t.Fatal("corrected port health failed to synchronize", current, monitor)
	}
	if f.successfulEvents() != 0 || !reflect.DeepEqual(g.UserIDs, current.UserIDs) || !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_member", "v2_node_address_rule", "v2_insider_rule")) {
		t.Fatal("correcting detection port changed dispatch or triggered automation")
	}
	servers, err := usersvc.NewDBService(f.s.cfg, f.db).Servers(f.ctx, 11, "")
	if err != nil || len(servers) == 0 || fmt.Sprint(servers[0]["host"]) != g.Host || fmt.Sprint(servers[0]["port"]) != "443" {
		t.Fatal("detection port changed subscription endpoint", servers, err)
	}
}
