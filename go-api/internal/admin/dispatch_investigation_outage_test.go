package admin

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	usersvc "forest/go-api/internal/user"
)

func TestInvestigationTCPFailureKeepsOriginalCutoff(t *testing.T) {
	c, samples := timestampEvidence(false)
	samples[len(samples)-1].Success = true
	first := samples[len(samples)-2].ReportedAt
	epoch := samples[len(samples)-1].ReportedAt - 100
	for _, index := range []int{20, 21, 23} {
		v := append([]DispatchHistorySample{}, samples...)
		v[index].Error = "connect_error"
		got, reason := investigationTimeoutEvidence(v, c, c.Reported, epoch, 0, 600)
		if reason != "" || got != first {
			t.Fatalf("index=%d: lost original cutoff: %d %s", index, got, reason)
		}
	}
	// A recent non-timeout TCP failure restarts only the timer. Manual execution
	// skips that wait, but still uses the earlier, established receipt cutoff.
	v := append([]DispatchHistorySample{}, samples...)
	v[8].Error = "connect_error"
	if _, reason := investigationTimeoutEvidence(v, c, c.Reported, epoch, 0, 600); !strings.Contains(reason, "未满 10 分钟") {
		t.Fatal("short timeout tail accepted or wrong explanation", reason)
	}
	if got, reason := investigationTimeoutEvidence(v, c, c.Reported, epoch, 0, 0); reason != "" || got != first {
		t.Fatal("manual trigger lost old receipts", got, reason)
	}
	// Neither a recovery nor a new confirmation is allowed to borrow that cutoff.
	v[8].Success = true
	if got, reason := investigationTimeoutEvidence(v, c, c.Reported, epoch, 0, 0); reason != "" || got != v[7].ReportedAt {
		t.Fatal("recovery did not delimit a new incident", got, reason)
	}
}

func TestInvestigationMixedFailureRetainsEvidenceGuards(t *testing.T) {
	c, baseline := timestampEvidence(false)
	baseline[len(baseline)-1].Success = true
	epoch := baseline[len(baseline)-1].ReportedAt - 100
	for _, kind := range []string{"dns", "cancelled", "unknown", "empty", "gap", "completion_gap", "sequence", "version", "session", "epoch", "unknown_start", "stale", "current_connect"} {
		t.Run(kind, func(t *testing.T) {
			v := append([]DispatchHistorySample{}, baseline...)
			candidate, from, now := c, epoch, c.Reported
			v[20].Error = "connect_error"
			switch kind {
			case "dns":
				v[21].Error = "dns_error"
			case "cancelled":
				v[21].Error = "cancelled"
			case "unknown":
				v[21].Error = "unexpected"
			case "empty":
				v[21].Error = ""
			case "gap":
				v[21].ReportedAt -= 50
			case "completion_gap":
				v[21].Sequence -= int64(50 * time.Second)
			case "sequence":
				v[21].Sequence = v[20].Sequence
			case "version":
				v[21].Version++
			case "session":
				v[21].RunID++
			case "epoch":
				from = baseline[22].ReportedAt
			case "unknown_start":
				v = v[:len(v)-1]
			case "stale":
				now += 120
			case "current_connect":
				candidate.Error = "connect_error"
				v[0].Error = "connect_error"
			}
			for _, duration := range []int64{0, 600} {
				if _, reason := investigationTimeoutEvidence(v, candidate, now, from, 0, duration); reason == "" {
					t.Fatal("unsafe evidence accepted", duration)
				}
			}
		})
	}
	// Explicit confirmations retain their own generation boundary and can also
	// survive a TCP error without inventing a successful sample.
	v := append([]DispatchHistorySample{}, baseline...)
	v[len(v)-1].Success = false
	v[20].Error = "connect_error"
	confirmed := v[len(v)-1].ReportedAt
	if got, reason := investigationTimeoutEvidence(v, c, c.Reported, confirmed, confirmed, 600); reason != "" || got != confirmed {
		t.Fatal("valid confirmed baseline rejected", got, reason)
	}
}

func TestPostgresInvestigationMixedFailureUsesOriginalRoundReceipts(t *testing.T) {
	for _, immediate := range []bool{false, true} {
		t.Run(map[bool]string{false: "automatic", true: "immediate"}[immediate], func(t *testing.T) {
			f := newInvestigationIntegration(t)
			f.pool("192.0.2.211", "192.0.2.212")
			g := f.group("range.example")
			f.outage(g, []int64{11, 12, 13})
			g = f.group(g.Host)
			var latest int64
			if err := f.db.QueryRow(`SELECT reported_at FROM v2_dispatch_monitor_state WHERE monitor_id=$1 AND probe_id=$2`, g.MonitorID, f.pid).Scan(&latest); err != nil {
				t.Fatal(err)
			}
			first := latest - 630
			for _, table := range []string{"v2_dispatch_investigation_delivery", "v2_dispatch_investigation_delivery_recent"} {
				f.exec(`UPDATE `+table+` SET delivered_at=$2 WHERE group_id=$1`, g.ID, first-5)
			}
			// Forty-three failure samples, one prior success. The connection error
			// is inside the incident; there are exactly 600 seconds of later timeout.
			f.exec(`DELETE FROM v2_dispatch_history WHERE source='entry' AND target_id=$1`, g.MonitorID)
			var version, run int64
			if err := f.db.QueryRow(`SELECT m.version,b.run_id FROM v2_dispatch_monitor m JOIN v2_dispatch_monitor_probe b ON b.monitor_id=m.id WHERE m.id=$1 AND b.probe_id=$2`, g.MonitorID, f.pid).Scan(&version, &run); err != nil {
				t.Fatal(err)
			}
			for n := int64(0); n < 44; n++ {
				at := latest - (43-n)*15
				success, fault := n == 0, "timeout"
				if success {
					fault = ""
				}
				if n == 2 {
					fault = "connect_error"
				}
				seq := at*int64(time.Second) + n
				sample := DispatchHistorySample{Source: "entry", TargetID: g.MonitorID, ProbeID: f.pid, Version: 1, RunID: 1, Sequence: seq, Success: success, Error: fault, ReportedAt: at}
				sample.Version, sample.RunID = version, run
				raw, _ := json.Marshal(sample)
				f.exec(`INSERT INTO v2_dispatch_history(source,target_id,probe_id,version,run_id,sequence,kind,host,port,success,payload,created_at) VALUES('entry',$1,$2,$3,$4,$5,'sample',$6,18443,$7,$8,$9)`, g.MonitorID, f.pid, version, run, seq, g.Host, success, string(raw), at)
				if n == 43 {
					f.exec(`UPDATE v2_dispatch_monitor_state SET sequence=$3,reported_at=$4 WHERE monitor_id=$1 AND probe_id=$2`, g.MonitorID, f.pid, seq, at)
				}
			}
			// These users pulled before the timeout timer restarted, but AFTER the
			// actual first failure. They must remain in observation, not candidates.
			for _, id := range []int64{14, 16} {
				if err := usersvc.NewDBService(f.s.cfg, f.db).RecordInvestigationDelivery(f.ctx, id, []usersvc.InvestigationDelivery{{GroupID: g.ID, Generation: g.Generation, Host: g.Host}}, first+5); err != nil {
					t.Fatal(err)
				}
			}
			if immediate {
				if err := f.s.TriggerInvestigation(f.ctx, InvestigationAction{ID: g.ID, Revision: g.Revision}); err != nil {
					t.Fatal(err)
				}
			} else {
				f.execProcess(g.ID)
			}
			if f.successfulEvents() != 1 {
				t.Fatal("did not filter", f.groups())
			}
			var cutoff, generation, epoch int64
			if err := f.db.QueryRow(`SELECT first_failure_at FROM v2_dispatch_investigation_event WHERE group_id=$1 AND kind='filtered'`, g.ID).Scan(&cutoff); err != nil {
				t.Fatal(err)
			}
			if err := f.db.QueryRow(`SELECT generation,epoch_at FROM v2_dispatch_investigation_group WHERE id=$1`, g.ID).Scan(&generation, &epoch); err != nil {
				t.Fatal(err)
			}
			if cutoff != first || generation != g.Generation || epoch != g.EpochAt {
				t.Fatal("old observation changed", cutoff, generation, epoch, g)
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
					t.Fatal("wrong original cutoff membership", child)
				}
				f.assertCheckPort(child.Host, 18443)
				for _, id := range investigationGroupIDs(child) {
					servers, err := usersvc.NewDBService(f.s.cfg, f.db).Servers(f.ctx, id, "")
					if err != nil || len(servers) == 0 || fmt.Sprint(servers[0]["host"]) != child.Host || fmt.Sprint(servers[0]["port"]) != "443" {
						t.Fatal("dispatch differs", servers, err)
					}
				}
			}
		})
	}
}
