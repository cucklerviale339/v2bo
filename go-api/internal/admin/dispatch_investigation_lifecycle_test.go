package admin

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	usersvc "forest/go-api/internal/user"
)

func TestInvestigationEpisodeAndVerificationAreIndependent(t *testing.T) {
	c, samples := timestampEvidence(false)
	samples[len(samples)-1].Success = true
	first := samples[len(samples)-2].ReportedAt
	epoch := samples[len(samples)-1].ReportedAt - 100
	for i := 0; i < len(samples)-1; i += 2 {
		samples[i].Error = "connect_error"
	}
	for _, fault := range []string{"timeout", "connect_error"} {
		c.Error = fault
		samples[0].Error = fault
		if got, reason := investigationTimeoutEvidence(samples, c, c.Reported, epoch, 0, 600); reason != "" || got != first {
			t.Fatal(fault, got, reason)
		}
	}
	// Reproduce the observed 51-second restart gap, followed by ten minutes of
	// alternating timeout/connect_error. Downtime cannot count toward that span.
	v := append([]DispatchHistorySample{}, samples...)
	for i := 21; i < len(v); i++ {
		v[i].ReportedAt -= 18
		v[i].Sequence -= 18 * int64(time.Second)
	}
	v[20].RecordedRestartBefore = true
	anchor := investigationIncidentFrom(v, c, epoch-100, 0, investigationIncident{})
	if anchor.Uncertain || !anchor.Baseline || anchor.First != first-18 {
		t.Fatal(anchor)
	}
	if !investigationFailureWindow(v, c, c.Reported, 600) {
		t.Fatal("post-restart observation failed")
	}
	// A restart only two samples ago must still wait, even after a long outage.
	v[20].RecordedRestartBefore = false
	v[1].RecordedRestartBefore = true
	if investigationFailureWindow(v, c, c.Reported, 600) {
		t.Fatal("downtime counted toward confirmation")
	}
	// An unexplained gap is different: the old cutoff is retained for a human,
	// but automatic inference is explicitly uncertain.
	v[1].RecordedRestartBefore = false
	anchor = investigationIncidentFrom(v, c, epoch-100, 0, investigationIncident{})
	if !anchor.Uncertain || anchor.First != first-18 {
		t.Fatal(anchor)
	}
}

func TestInvestigationFinalProbeResultDefinesFailure(t *testing.T) {
	for _, fault := range []string{"timeout", "connect_error", "dns_error", "cancelled", "unexpected", ""} {
		t.Run(fault, func(t *testing.T) {
			c, samples := timestampEvidence(false)
			samples[len(samples)-1].Success = true
			first := samples[len(samples)-2].ReportedAt
			for i := 0; i < len(samples)-1; i += 2 {
				samples[i].Error = fault
			}
			c.Error = fault
			if got, reason := investigationTimeoutEvidence(samples, c, c.Reported, first-100, 0, 600); reason != "" || got != first {
				t.Fatal("error label blocked a final failed result", got, reason)
			}
			// The exact same failure sequence without any real prior success
			// must never acquire an automatic baseline from a human confirmation.
			samples[len(samples)-1].Success = false
			epoch := samples[len(samples)-1].ReportedAt
			if _, reason := investigationTimeoutEvidence(samples, c, c.Reported, epoch, epoch, 600); reason == "" {
				t.Fatal("never-healthy entry triggered automatically")
			}
		})
	}
}

func TestInvestigationRestartAndBufferedReceiptsCannotManufactureContinuity(t *testing.T) {
	c, samples := timestampEvidence(false)
	samples[len(samples)-1].Success = true
	// Even a short unexplained transition between runs suspends automation.
	samples[1].UnverifiedRestartBefore = true
	incident := investigationIncidentFrom(samples, c, c.Reported-1000, 0, investigationIncident{})
	if !incident.Uncertain || investigationFailureWindow(samples, c, c.Reported, 600) {
		t.Fatal("unverified run transition accepted")
	}
	samples[1].UnverifiedRestartBefore = false
	// Many buffered checks spread across receipt times are not ten minutes
	// of probe completion evidence.
	for i := range samples {
		samples[i].Sequence = c.Sequence - int64(i)*int64(time.Second)
	}
	if investigationFailureWindow(samples, c, c.Reported, 600) {
		t.Fatal("buffered completion burst counted as ten minutes")
	}
}

func TestInvestigationIncidentSurvivesRetentionAndRecovery(t *testing.T) {
	c, samples := timestampEvidence(false)
	samples[len(samples)-1].Success = true
	first := samples[len(samples)-2].ReportedAt
	epoch := samples[len(samples)-1].ReportedAt - 10
	saved := investigationIncidentFrom(samples, c, epoch, 0, investigationIncident{})
	trimmed := samples[:len(samples)-3]
	next := investigationIncidentFrom(trimmed, c, epoch, 0, saved)
	if next.First != first || !next.Baseline || next.Uncertain {
		t.Fatal("retention shifted cutoff", saved, next)
	}
	// Same generation, actual recovery: end the old episode and use the next
	// first failure. An old persisted cutoff cannot override this success.
	trimmed = append([]DispatchHistorySample{}, trimmed...)
	trimmed[4].Success = true
	next = investigationIncidentFrom(trimmed, c, epoch, 0, saved)
	if next.First != trimmed[3].ReportedAt || !next.Baseline {
		t.Fatal("recovery reused old cutoff", next)
	}
	// Without the persisted observation in the replay the baseline is unknown.
	trimmed = trimmed[1:]
	trimmed[3].Success = false
	next = investigationIncidentFrom(trimmed, c, epoch, 0, saved)
	if next.Baseline {
		t.Fatal("unrelated checkpoint borrowed", next)
	}
	if next.First != saved.First || !next.Uncertain {
		t.Fatal("missing history erased manual anchor", next)
	}
	next = investigationIncidentFrom(nil, c, epoch, 0, saved)
	if next.First != saved.First || !next.Uncertain {
		t.Fatal("empty history erased manual anchor", next)
	}
}

func (f *investigationIntegration) restartEpisode(g InvestigationGroup, postSamples int) (int64, int64) {
	f.t.Helper()
	f.outage(g, []int64{11, 12, 13})
	g = f.group(g.Host)
	latest := time.Now().Unix()
	first := latest - 1500
	var version, oldRun int64
	if err := f.db.QueryRow(`SELECT m.version,b.run_id FROM v2_dispatch_monitor m JOIN v2_dispatch_monitor_probe b ON b.monitor_id=m.id WHERE m.id=$1 AND b.probe_id=$2`, g.MonitorID, f.pid).Scan(&version, &oldRun); err != nil {
		f.t.Fatal(err)
	}
	f.exec(`DELETE FROM v2_dispatch_history WHERE source='entry' AND target_id=$1`, g.MonitorID)
	insert := func(at, run int64, success bool, fault string) {
		seq := at * int64(time.Second)
		x := DispatchHistorySample{Version: version, RunID: run, Sequence: seq, ReportedAt: at, Success: success, Error: fault}
		raw, _ := json.Marshal(x)
		f.exec(`INSERT INTO v2_dispatch_history(source,target_id,probe_id,version,run_id,sequence,kind,host,port,success,payload,created_at) VALUES('entry',$1,$2,$3,$4,$5,'sample',$6,18443,$7,$8,$9)`, g.MonitorID, f.pid, version, run, seq, g.Host, success, string(raw), at)
	}
	postFirst := latest - int64(postSamples-1)*30
	preLast := postFirst - 51
	insert(first-30, oldRun, true, "")
	for at := first; at < preLast; at += 30 {
		insert(at, oldRun, false, "timeout")
	}
	insert(preLast, oldRun, false, "connect_error")
	f.exec(`INSERT INTO v2_dispatch_monitor_restart(monitor_id,probe_id,version,from_run,to_run,created_at) VALUES($1,$2,$3,$4,$5,$6)`, g.MonitorID, f.pid, version, oldRun, oldRun+1, preLast+10)
	f.exec(`UPDATE v2_dispatch_monitor_probe SET run_id=run_id+1 WHERE monitor_id=$1 AND probe_id=$2`, g.MonitorID, f.pid)
	for n := 0; n < postSamples; n++ {
		fault := "timeout"
		if n%2 == 0 {
			fault = "connect_error"
		}
		insert(postFirst+int64(n)*30, oldRun+1, false, fault)
	}
	fault := "timeout"
	if (postSamples-1)%2 == 0 {
		fault = "connect_error"
	}
	f.exec(`UPDATE v2_dispatch_monitor_state SET sequence=$3,reported_at=$4,error=$5 WHERE monitor_id=$1 AND probe_id=$2`, g.MonitorID, f.pid, latest*int64(time.Second), latest, fault)
	f.exec(`UPDATE v2_dispatch_investigation_group SET epoch_at=$2,ready_at=$2 WHERE id=$1`, g.ID, first-100)
	f.exec(`UPDATE v2_dispatch_investigation_settings SET armed_at=$1`, first-100)
	for _, table := range []string{"v2_dispatch_investigation_delivery", "v2_dispatch_investigation_delivery_recent"} {
		f.exec(`UPDATE `+table+` SET delivered_at=$2 WHERE group_id=$1`, g.ID, first-5)
	}
	// Users who pull during restart downtime must not enter the candidate set.
	if err := usersvc.NewDBService(f.s.cfg, f.db).RecordInvestigationDelivery(f.ctx, 14, []usersvc.InvestigationDelivery{{GroupID: g.ID, Generation: g.Generation, Host: g.Host}}, preLast+20); err != nil {
		f.t.Fatal(err)
	}
	return first, latest
}

func TestPostgresInvestigationRestartEpisodeWithMixedFailures(t *testing.T) {
	for _, count := range []int{2, 22} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			f := newInvestigationIntegration(t)
			f.pool("192.0.2.211", "192.0.2.212")
			g := f.group("range.example")
			first, _ := f.restartEpisode(g, count)
			if count == 22 {
				// Older startup rows used PostgreSQL's rounding epoch cast;
				// their timestamp can be one second ahead of a Go receipt.
				f.exec(`UPDATE v2_dispatch_monitor_restart r SET created_at=(SELECT min(h.created_at)+1 FROM v2_dispatch_history h WHERE h.source='entry' AND h.target_id=r.monitor_id AND h.probe_id=r.probe_id AND h.run_id=r.to_run) WHERE monitor_id=$1`, g.MonitorID)
			}
			g = f.group(g.Host)
			f.execProcess(g.ID)
			if count == 2 {
				if f.successfulEvents() != 0 {
					t.Fatal("restart skipped verification")
				}
				g = f.group(g.Host)
				if err := f.s.TriggerInvestigation(f.ctx, InvestigationAction{ID: g.ID, Revision: g.Revision}); err != nil {
					t.Fatal(err)
				}
			}
			if f.successfulEvents() != 1 {
				t.Fatal("restart stuck", f.groups())
			}
			var cutoff int64
			if err := f.db.QueryRow(`SELECT first_failure_at FROM v2_dispatch_investigation_event WHERE group_id=$1 AND kind='filtered'`, g.ID).Scan(&cutoff); err != nil || cutoff != first {
				t.Fatal(cutoff, first, err)
			}
			for _, child := range f.groups() {
				if child.ParentID != g.ID {
					continue
				}
				want := []string{"11", "12", "13"}
				if child.Kind == "observation" {
					want = []string{"14", "15", "16", "17", "42"}
				}
				if !reflect.DeepEqual(child.UserIDs, want) {
					t.Fatal(child)
				}
				f.assertCheckPort(child.Host, 18443)
			}
		})
	}
}

func TestPostgresInvestigationManualExecutionIndependentOfDiagnosis(t *testing.T) {
	for _, kind := range []string{"unknown_start", "no_history", "report_gap", "no_control", "cooldown", "global", "offline", "healthy", "dns_error", "empty_state"} {
		t.Run(kind, func(t *testing.T) {
			f := newInvestigationIntegration(t)
			f.pool("192.0.2.211", "192.0.2.212")
			g := f.group("range.example")
			f.outage(g, []int64{11, 12, 13})
			g = f.group(g.Host)
			switch kind {
			case "unknown_start":
				f.exec(`UPDATE v2_dispatch_history SET success=FALSE,payload=jsonb_set(jsonb_set(payload,'{success}','false'::jsonb),'{error}','"timeout"'::jsonb) WHERE source='entry' AND target_id=$1`, g.MonitorID)
			case "no_history":
				f.exec(`DELETE FROM v2_dispatch_history WHERE source='entry' AND target_id=$1`, g.MonitorID)
			case "report_gap":
				f.exec(`UPDATE v2_dispatch_history SET created_at=created_at-120,payload=jsonb_set(payload,'{reported_at}',to_jsonb(created_at-120)) WHERE source='entry' AND target_id=$1 AND sequence<12`, g.MonitorID)
			case "no_control":
				f.exec(`UPDATE v2_dispatch_monitor_state SET success=FALSE WHERE monitor_id<>$1`, g.MonitorID)
			case "cooldown":
				f.exec(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload) VALUES($1,$1,'filtered',$2,'{}')`, g.RootID, time.Now().Unix())
			case "global":
				f.exec(`UPDATE v2_dispatch_investigation_settings SET global_max=1`)
				f.exec(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload) VALUES(999,999,'filtered',$1,'{}')`, time.Now().Unix())
			case "offline":
				// Pool eligibility still requires a fresh healthy probe. Make only the
				// source state stale; independent pool observations remain usable.
				f.exec(`UPDATE v2_dispatch_monitor_state SET reported_at=reported_at-300 WHERE monitor_id=$1`, g.MonitorID)
			case "healthy":
				f.exec(`UPDATE v2_dispatch_monitor_state SET success=TRUE,error='' WHERE monitor_id=$1`, g.MonitorID)
			case "dns_error":
				f.exec(`UPDATE v2_dispatch_monitor_state SET error='dns_error' WHERE monitor_id=$1`, g.MonitorID)
			case "empty_state":
				f.exec(`DELETE FROM v2_dispatch_monitor_state WHERE monitor_id=$1`, g.MonitorID)
			}
			var before int
			f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_event WHERE kind IN('filtered','bisected','no_pulls')`).Scan(&before)
			if err := f.s.TriggerInvestigation(f.ctx, InvestigationAction{ID: g.ID, Revision: g.Revision}); err != nil {
				t.Fatal(err)
			}
			if f.successfulEvents() != before+1 {
				t.Fatal("manual did not execute", f.groups())
			}
			var mode, source string
			if err := f.db.QueryRow(`SELECT payload->'evidence'->>'mode',payload->'evidence'->>'cutoff_source' FROM v2_dispatch_investigation_event WHERE group_id=$1 AND kind='manual_trigger'`, g.ID).Scan(&mode, &source); err != nil || mode != "manual" {
				t.Fatal(mode, source, err)
			}
			if kind == "no_history" && source != "manual_snapshot" {
				t.Fatal(source)
			}
			if err := f.s.TriggerInvestigation(f.ctx, InvestigationAction{ID: g.ID, Revision: g.Revision}); err == nil {
				t.Fatal("duplicate manual execution")
			}
		})
	}
}

func TestPostgresInvestigationControlsAfterSharedRestart(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.group("range.example")
	first, latest := f.restartEpisode(g, 24)
	// The same service restart changes controls' runs too. Their new-run
	// healthy observations span the current window, without requiring them
	// to bridge the old outage or the startup gap.
	f.exec(`INSERT INTO v2_dispatch_monitor_restart(monitor_id,probe_id,version,from_run,to_run,created_at) SELECT b.monitor_id,b.probe_id,m.version,b.run_id,b.run_id+1,$2 FROM v2_dispatch_monitor_probe b JOIN v2_dispatch_monitor m ON m.id=b.monitor_id WHERE m.id<>$1`, g.MonitorID, latest-731)
	f.exec(`UPDATE v2_dispatch_history SET run_id=run_id+1,payload=jsonb_set(payload,'{run_id}',to_jsonb(run_id+1)) WHERE source='entry' AND target_id<>$1`, g.MonitorID)
	f.exec(`UPDATE v2_dispatch_monitor_probe SET run_id=run_id+1 WHERE monitor_id<>$1`, g.MonitorID)
	f.exec(`UPDATE v2_dispatch_history SET payload=jsonb_set(payload,'{error}',to_jsonb(CASE WHEN sequence%2=0 THEN 'dns_error' ELSE 'cancelled' END)) WHERE source='entry' AND target_id=$1 AND NOT success`, g.MonitorID)
	f.exec(`UPDATE v2_dispatch_monitor_state SET error='dns_error' WHERE monitor_id=$1`, g.MonitorID)
	f.execProcess(g.ID)
	if f.successfulEvents() != 1 {
		t.Fatal("shared restart or alternating final errors blocked execution", f.groups())
	}
	var cutoff int64
	if err := f.db.QueryRow(`SELECT first_failure_at FROM v2_dispatch_investigation_event WHERE group_id=$1 AND kind='filtered'`, g.ID).Scan(&cutoff); err != nil || cutoff != first {
		t.Fatal("shared restart moved cutoff", cutoff, first, err)
	}
}

func TestPostgresInvestigationManualProductionSizedGroup(t *testing.T) {
	f := &investigationIntegration{newSplitIntegration(t)}
	f.exec(`INSERT INTO v2_user(id,email,password,uuid,token,group_id,plan_id,transfer_enable,created_at,updated_at) SELECT id,'large-'||id||'@example.test','hash','00000000-0000-0000-0000-'||lpad(id::text,12,'0'),lpad(id::text,32,'0'),1,1,1000000,1,1 FROM generate_series(10,4516) id ON CONFLICT(id) DO NOTHING`)
	f.exec(`UPDATE v2_node_address_rule SET match_user_id_ranges='["10-4516"]' WHERE host='range.example'`)
	if err := f.s.ensureInvestigation(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.s.SaveInvestigation(f.ctx, InvestigationSettings{Enabled: true, Revision: 1, EntryWindowMinutes: 20, GlobalWindowMinutes: 60, GlobalMax: 3}); err != nil {
		t.Fatal(err)
	}
	if err := f.s.bootstrapInvestigation(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.group("range.example")
	if len(g.UserIDs) != 4507 {
		t.Fatal("production-sized membership not established", len(g.UserIDs))
	}
	f.outage(g, []int64{11, 12, 13})
	g = f.group(g.Host)
	if err := f.s.TriggerInvestigation(f.ctx, InvestigationAction{ID: g.ID, Revision: g.Revision}); err != nil {
		t.Fatal("production-sized manual execution failed", err)
	}
	if f.successfulEvents() != 1 {
		t.Fatal("production-sized manual execution was incomplete")
	}
	for _, child := range f.groups() {
		if child.ParentID != g.ID {
			continue
		}
		want := 3
		if child.Kind == "observation" {
			want = 4504
		}
		if len(child.UserIDs) != want {
			t.Fatal("incorrect production-sized partition", child.Kind, len(child.UserIDs))
		}
		f.assertCheckPort(child.Host, 18443)
		id := investigationGroupIDs(child)[0]
		nodes, err := usersvc.NewDBService(f.s.cfg, f.db).Servers(f.ctx, id, "")
		if err != nil || len(nodes) == 0 || fmt.Sprint(nodes[0]["host"]) != child.Host || fmt.Sprint(nodes[0]["port"]) != "443" {
			t.Fatal("large-group subscription was not switched correctly", nodes, err)
		}
	}
}
