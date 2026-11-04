package admin

import (
	"fmt"
	"testing"
	"time"

	usersvc "forest/go-api/internal/user"
)

// Match probeagent.runTask: ResultID ends in time.Now().UnixNano(), not an
// incrementing counter. Use irregular completion times, as real TCP checks do.
func timestampEvidence(success bool) (dispatchSplitCandidate, []DispatchHistorySample) {
	now := int64(1793684346)
	seq := now*int64(time.Second) + 587817875
	c := dispatchSplitCandidate{Version: 2, RunID: 4, Sequence: seq, Interval: 30, Timeout: 3000, Reported: now, Success: success, Error: "timeout"}
	if success {
		c.Error = ""
	}
	samples := []DispatchHistorySample{}
	for i := int64(0); i < 25; i++ {
		at := now - i*33
		v := DispatchHistorySample{Version: c.Version, RunID: c.RunID, Sequence: seq - i*33*int64(time.Second) - i*1731, ReportedAt: at, Success: success, Error: c.Error}
		samples = append(samples, v)
	}
	return c, samples
}

// Replay the real wire format through ReportDispatchProbeResults after moving
// fixture history to UnixNano IDs. Both failed targets and healthy controls
// must use that format, otherwise the original production bug is missed.
func TestPostgresTimestampProbeTriggersInvestigation(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.201", "192.0.2.202")
	g := f.group("range.example")
	f.outage(g, []int64{11, 12, 13})
	f.timestampHistory()
	task := f.tasks(f.pid)[g.Host]
	no := false
	seq := time.Now().UnixNano()
	r, err := f.s.ReportDispatchProbeResults(f.ctx, f.pid, DNSProbeResultsRequest{Results: []DNSProbeResult{{ResultID: fmt.Sprintf("%d-%d", task.TargetID, seq), TargetID: task.TargetID, TargetVersion: task.TargetVersion, RunID: task.RunID, Success: &no, Error: "timeout"}}})
	if err != nil || r.Accepted != 1 {
		t.Fatal("real probe wire format rejected", r, err)
	}
	f.execProcess(g.ID)
	if f.successfulEvents() != 1 {
		t.Fatal("timestamp failure/control evidence did not trigger filtering", f.groups())
	}
	for _, child := range f.groups() {
		if child.ParentID != g.ID {
			continue
		}
		f.assertCheckPort(child.Host, 18443)
		for _, id := range investigationGroupIDs(child) {
			servers, err := usersvc.NewDBService(f.s.cfg, f.db).Servers(f.ctx, id, "")
			if err != nil || len(servers) == 0 || fmt.Sprint(servers[0]["host"]) != child.Host || fmt.Sprint(servers[0]["port"]) != "443" {
				t.Fatal("timestamp-triggered switch did not reach actual subscription", servers, err)
			}
		}
	}
	// A second execution must not consume another pair of addresses.
	f.execProcess(g.ID)
	if f.successfulEvents() != 1 {
		t.Fatal("same incident executed twice")
	}
}

func (f *splitIntegration) timestampHistory() {
	f.t.Helper()
	// Keep event/sample identities equal and make current state reference the
	// exact latest history row, as real accepted timestamp IDs do.
	f.exec(`UPDATE v2_dispatch_monitor_state st SET sequence=h.created_at*1000000000+h.sequence FROM v2_dispatch_history h WHERE h.source='entry' AND h.kind='sample' AND h.target_id=st.monitor_id AND h.probe_id=st.probe_id AND h.version=st.version AND h.sequence=st.sequence`)
	f.exec(`UPDATE v2_dispatch_history SET payload=jsonb_set(payload,'{sequence}',to_jsonb(created_at*1000000000+sequence)),sequence=created_at*1000000000+sequence WHERE source='entry'`)
}

func TestPostgresTimestampProbeTriggersFailover(t *testing.T) {
	f := newSplitIntegration(t)
	f.pool("192.0.2.211", "192.0.2.212")
	f.enable()
	f.timeout("range.example")
	f.timestampHistory()
	states, err := dispatchSplitStates(f.ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	var c dispatchSplitCandidate
	for _, state := range states {
		if state.Host == "range.example" {
			c = state
		}
	}
	if !f.process(c) || f.successes() != 1 {
		t.Fatal("real timestamp sequences did not trigger failover", f.view())
	}
	op := f.view().Operations[0]
	f.assertCheckPort(op.IPA, 18443)
	f.assertCheckPort(op.IPB, 18443)
}

func TestTimestampEvidenceAcrossAutomaticSystems(t *testing.T) {
	c, failures := timestampEvidence(false)
	if !dispatchTimeoutSpan(failures, c, c.Reported, c.Reported-1000) {
		t.Fatal("real timestamp sequences rejected by failover")
	}
	failures[len(failures)-1].Success = true
	failures[len(failures)-1].Error = ""
	first, ok := investigationTimeoutStart(failures, c, c.Reported, c.Reported-1000)
	if !ok || first != failures[len(failures)-2].ReportedAt {
		t.Fatal("real timestamp sequences rejected by investigation", first, ok)
	}
	control, normal := timestampEvidence(true)
	if !investigationControlSpan(normal, control, c.Reported-660, c.Reported) {
		t.Fatal("real timestamp sequences rejected as normal controls")
	}
}

func TestTimestampEvidenceRejectsBrokenContinuity(t *testing.T) {
	for _, name := range []string{"missing_sample", "duplicate", "reversed", "session", "version", "receive_gap", "old_latest", "mixed_sequence", "recovery", "other_error"} {
		t.Run(name, func(t *testing.T) {
			c, samples := timestampEvidence(false)
			switch name {
			case "missing_sample":
				samples = append(samples[:8], samples[9:]...)
			case "duplicate":
				samples[8].Sequence = samples[7].Sequence
			case "reversed":
				samples[8].Sequence = samples[7].Sequence + 1
			case "session":
				samples[8].RunID--
			case "version":
				samples[8].Version--
			case "receive_gap":
				samples[8].ReportedAt -= 200
			case "old_latest":
				samples[0].Sequence--
			case "mixed_sequence":
				samples[8].Sequence = 10
			case "recovery":
				samples[8].Success = true
			case "other_error":
				samples[8].Error = "dns_error"
			}
			if dispatchTimeoutSpan(samples, c, c.Reported, c.Reported-1000) {
				t.Fatal("failover accepted broken evidence")
			}
			// Ensure a valid beginning exists beyond the broken section.
			samples[len(samples)-1].Success = true
			if _, ok := investigationTimeoutStart(samples, c, c.Reported, c.Reported-1000); ok && name != "other_error" {
				t.Fatal("investigation accepted broken evidence")
			}
			if name == "recovery" || name == "other_error" {
				return
			}
			c.Success, c.Error = true, ""
			for i := range samples {
				samples[i].Success, samples[i].Error = true, ""
			}
			if investigationControlSpan(samples, c, c.Reported-660, c.Reported) {
				t.Fatal("normal control accepted broken evidence")
			}
		})
	}
}
