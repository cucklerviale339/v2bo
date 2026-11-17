package admin

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	usersvc "forest/go-api/internal/user"
)

func TestInvestigationReceiptDelayUsesCompletionEvidence(t *testing.T) {
	for _, delay := range []int64{15, 35, 36} {
		c, samples := timestampEvidence(false)
		samples[len(samples)-1].Success = true
		first := samples[len(samples)-2].ReportedAt
		// Real checks remain 33 seconds apart. One delayed server receipt makes
		// the apparent interval 48 seconds (or the 68-second allowed boundary).
		for i := 0; i <= 8; i++ {
			samples[i].ReportedAt += delay
		}
		c.Reported += delay
		// Old versions persisted uncertain=true for this exact observation.
		saved := investigationIncident{First: first, LastSuccess: samples[len(samples)-1].ReportedAt, Baseline: true, Uncertain: true, Sequence: c.Sequence, Reported: c.Reported}
		incident := investigationIncidentFrom(samples, c, first-100, 0, saved)
		got, reason := investigationAutomaticDecision(incident, samples, c, c.Reported, 600)
		if delay <= 35 {
			if incident.Uncertain || got != first || reason != "" {
				t.Fatalf("delay=%d: valid completion history stayed blocked: %+v, %d %s", delay, incident, got, reason)
			}
		} else if !incident.Uncertain || reason == "" {
			t.Fatal("long report outage accepted", incident, reason)
		}
		// Controls need the same transport allowance as the failed target.
		for i := range samples {
			samples[i].Success = true
		}
		c.Success = true
		if ok := investigationControlSpan(samples, c, c.Reported-600, c.Reported); ok != (delay <= 35) {
			t.Fatal("target/control delay rules differ", delay, ok)
		}
	}
}

func TestEvidenceReceiptDelayCannotHideMissingChecks(t *testing.T) {
	c, samples := timestampEvidence(false)
	older, newer := samples[9], samples[8]
	newer.ReportedAt += 15
	if !investigationEvidenceFollows(newer, older, c) {
		t.Fatal("48-second receipt gap with 33-second completion gap rejected")
	}
	if dispatchEvidenceFollows(newer, older, c) {
		t.Fatal("receipt allowance changed long-term observation or legacy failover")
	}
	newer.Sequence += 15 * int64(time.Second)
	if investigationEvidenceFollows(newer, older, c) {
		t.Fatal("48-second completion gap disguised as transport delay")
	}
	newer.Sequence, older.Sequence = 2, 1
	if investigationEvidenceFollows(newer, older, c) {
		t.Fatal("legacy counter borrowed timestamp transport allowance")
	}
	newer.Sequence = c.Sequence
	if investigationEvidenceFollows(newer, older, c) {
		t.Fatal("mixed sequence formats accepted")
	}
}

func TestPostgresInvestigationReceiptDelayRepairsStoredUncertainty(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.group("range.example")
	f.outage(g, []int64{11, 12, 13})
	g = f.group(g.Host)
	latest := time.Now().Unix()
	completion := latest - 15
	first := completion - 23*33
	baseline := first - 33
	var version, run int64
	if err := f.db.QueryRow(`SELECT m.version,b.run_id FROM v2_dispatch_monitor m JOIN v2_dispatch_monitor_probe b ON b.monitor_id=m.id WHERE m.id=$1 AND b.probe_id=$2`, g.MonitorID, f.pid).Scan(&version, &run); err != nil {
		t.Fatal(err)
	}
	f.exec(`DELETE FROM v2_dispatch_history WHERE source='entry' AND target_id=$1`, g.MonitorID)
	for i := int64(24); i >= 0; i-- {
		at := completion - i*33
		received := at
		if i <= 8 {
			received += 15
		}
		seq := at*int64(time.Second) + 123
		x := DispatchHistorySample{Version: version, RunID: run, Sequence: seq, ReportedAt: received, Success: i == 24, Error: "timeout"}
		if x.Success {
			x.Error = ""
		}
		raw, _ := json.Marshal(x)
		f.exec(`INSERT INTO v2_dispatch_history(source,target_id,probe_id,version,run_id,sequence,kind,host,port,success,payload,created_at) VALUES('entry',$1,$2,$3,$4,$5,'sample',$6,18443,$7,$8,$9)`, g.MonitorID, f.pid, version, run, seq, g.Host, x.Success, string(raw), received)
		if i == 0 {
			f.exec(`UPDATE v2_dispatch_monitor_state SET sequence=$3,reported_at=$4 WHERE monitor_id=$1 AND probe_id=$2`, g.MonitorID, f.pid, seq, received)
		}
	}
	f.exec(`UPDATE v2_dispatch_investigation_group SET epoch_at=$2,ready_at=$2 WHERE id=$1`, g.ID, baseline-10)
	f.exec(`UPDATE v2_dispatch_investigation_settings SET armed_at=$1`, baseline-10)
	for _, table := range []string{"v2_dispatch_investigation_delivery", "v2_dispatch_investigation_delivery_recent"} {
		f.exec(`UPDATE `+table+` SET delivered_at=$2 WHERE group_id=$1`, g.ID, first-5)
	}
	// A pull after the real failure but before delayed reports is not a suspect.
	if err := usersvc.NewDBService(f.s.cfg, f.db).RecordInvestigationDelivery(f.ctx, 14, []usersvc.InvestigationDelivery{{GroupID: g.ID, Generation: g.Generation, Host: g.Host}}, first+5); err != nil {
		t.Fatal(err)
	}
	f.exec(`INSERT INTO v2_dispatch_investigation_incident(group_id,generation,probe_id,version,first_failure_at,last_success_at,baseline,uncertain,sequence,reported_at) VALUES($1,$2,$3,$4,$5,$6,TRUE,TRUE,$7,$8) ON CONFLICT(group_id,generation,probe_id,version) DO UPDATE SET first_failure_at=EXCLUDED.first_failure_at,last_success_at=EXCLUDED.last_success_at,baseline=TRUE,uncertain=TRUE,sequence=EXCLUDED.sequence,reported_at=EXCLUDED.reported_at`, g.ID, g.Generation, f.pid, version, first, baseline, completion*int64(time.Second)+123, latest)
	f.execProcess(g.ID)
	if f.successfulEvents() != 1 {
		t.Fatal("delayed reports permanently blocked automatic filtering", f.groups())
	}
	var cutoff int64
	if err := f.db.QueryRow(`SELECT first_failure_at FROM v2_dispatch_investigation_event WHERE group_id=$1 AND kind='filtered'`, g.ID).Scan(&cutoff); err != nil || cutoff != first {
		t.Fatal("receipt delay moved original cutoff", cutoff, first, err)
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
			t.Fatal("old round receipt membership changed", child)
		}
		f.assertCheckPort(child.Host, 18443)
	}
	f.execProcess(g.ID)
	if f.successfulEvents() != 1 {
		t.Fatal("same delayed incident applied twice")
	}
}
