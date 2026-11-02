package admin

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"forest/go-api/internal/config"
	usersvc "forest/go-api/internal/user"
)

func TestDispatchTimeoutRequiresContinuousFreshEvidence(t *testing.T) {
	now := time.Now().Unix()
	c := dispatchSplitCandidate{Version: 1, RunID: 3, Sequence: 22, Interval: 30, Timeout: 500, Reported: now, Error: "timeout"}
	baseline := []DispatchHistorySample{}
	for i := int64(0); i < 22; i++ {
		baseline = append(baseline, DispatchHistorySample{Version: 1, RunID: 3, Sequence: 22 - i, ReportedAt: now - i*30, Error: "timeout"})
	}
	if !dispatchTimeoutSpan(baseline, c, now, now-700) {
		t.Fatal("continuous timeout rejected")
	}
	for _, tc := range []struct {
		name   string
		mutate func([]DispatchHistorySample)
	}{
		{"recovery", func(v []DispatchHistorySample) { v[10].Success = true }},
		{"other failure", func(v []DispatchHistorySample) { v[10].Error = "connect_error" }},
		{"old session", func(v []DispatchHistorySample) { v[10].RunID = 2 }},
		{"old version", func(v []DispatchHistorySample) { v[10].Version = 2 }},
		{"missing latest write", func(v []DispatchHistorySample) { v[0].Sequence-- }},
		{"missing intermediate write", func(v []DispatchHistorySample) { v[8].Sequence-- }},
		{"missing intermediate sample", func(v []DispatchHistorySample) {
			for i := 8; i < len(v); i++ {
				v[i].Sequence--
			}
		}},
		{"long reporting gap", func(v []DispatchHistorySample) {
			for i := 10; i < len(v); i++ {
				v[i].ReportedAt -= 120
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := append([]DispatchHistorySample{}, baseline...)
			tc.mutate(v)
			if dispatchTimeoutSpan(v, c, now, now-700) {
				t.Fatal("unsafe evidence accepted")
			}
		})
	}
	if dispatchTimeoutSpan(baseline[:10], c, now, now-700) || dispatchTimeoutSpan(baseline, c, now, now-300) || dispatchTimeoutSpan(baseline, c, now+100, now-700) {
		t.Fatal("accepted insufficient, newly armed or stale span")
	}
}

type splitIntegration struct {
	*dispatchDeleteIntegration
	pid int64
}

func newSplitIntegration(t *testing.T) *splitIntegration {
	f := newDispatchDeleteIntegration(t)
	f.exec(`DELETE FROM v2_insider_rule`)
	f.s.dispatchCatalog = usersvc.NewDBService(config.Config{}, f.db)
	pid := f.probe("auto split probe")
	f.save("range.example", pid)
	f.save("base.example", pid)
	f.report(pid, f.tasks(pid)["base.example"], 1, 1, 0)
	if err := f.s.ensureDispatchAutoSplitSchema(f.ctx); err != nil {
		t.Fatal(err)
	}
	return &splitIntegration{f, pid}
}
func (f *splitIntegration) enable() {
	f.t.Helper()
	if err := f.s.SaveDispatchAutoSplit(f.ctx, DispatchAutoSplitSettings{Enabled: true, EntryWindowMinutes: 20, GlobalWindowMinutes: 60, GlobalMax: 3}); err != nil {
		f.t.Fatal(err)
	}
	f.exec(`UPDATE v2_dispatch_auto_split_settings SET armed_at=$1`, time.Now().Unix()-720)
}
func (f *splitIntegration) pool(ips ...string) {
	f.t.Helper()
	items := []DispatchPoolSave{}
	for _, ip := range ips {
		items = append(items, DispatchPoolSave{IP: ip, Port: 18443, Enabled: true, CheckIntervalSec: 30, TCPTimeoutMS: 500})
	}
	if _, err := f.s.SaveDispatchPool(f.ctx, items); err != nil {
		f.t.Fatal(err)
	}
	tasks, err := f.s.ListDispatchCheckTasks(f.ctx, f.pid)
	if err != nil {
		f.t.Fatal(err)
	}
	yes, latency := true, int64(12)
	for _, task := range tasks {
		for seq := 1; seq <= 2; seq++ {
			_, err = f.s.ReportDispatchCheckResults(f.ctx, f.pid, DNSProbeResultsRequest{Results: []DNSProbeResult{{ResultID: fmt.Sprintf("qa-%d", seq), TargetID: task.TargetID, TargetVersion: task.TargetVersion, RunID: task.RunID, Success: &yes, LatencyMS: &latency}}})
			if err != nil {
				f.t.Fatal(err)
			}
		}
	}
}
func (f *splitIntegration) timeout(host string) dispatchSplitCandidate {
	f.t.Helper()
	f.s.dispatchCacheMu.Lock()
	f.s.dispatchCachedHosts = nil
	f.s.dispatchCacheAt = time.Time{}
	f.s.dispatchCacheMu.Unlock()
	task, ok := f.tasks(f.pid)[host]
	if !ok {
		f.t.Fatalf("missing task for %s", host)
	}
	no := false
	var first int64
	if err := f.db.QueryRow(`SELECT COALESCE(max(sequence),0) FROM v2_dispatch_monitor_state WHERE monitor_id=$1 AND probe_id=$2 AND version=$3`, -task.TargetID, f.pid, task.TargetVersion).Scan(&first); err != nil {
		f.t.Fatal(err)
	}
	// Use one accepted batch, then move server receipt timestamps to simulate
	// ten minutes without sleeping or weakening production timeout thresholds.
	results := []DNSProbeResult{}
	for seq := first + 1; seq <= first+22; seq++ {
		results = append(results, DNSProbeResult{ResultID: fmt.Sprintf("qa-%d", seq), TargetID: task.TargetID, TargetVersion: task.TargetVersion, RunID: task.RunID, Success: &no, Error: "timeout"})
	}
	r, err := f.s.ReportDispatchProbeResults(f.ctx, f.pid, DNSProbeResultsRequest{Results: results})
	if err != nil || r.Accepted != 22 {
		f.t.Fatalf("timeout reports %#v %v", r, err)
	}
	id := -task.TargetID
	now := time.Now().Unix()
	f.exec(`UPDATE v2_dispatch_history SET created_at=$1-($5::bigint-sequence)*30,payload=jsonb_set(payload,'{reported_at}',to_jsonb($1::bigint-($5::bigint-sequence)*30)) WHERE source='entry' AND target_id=$2 AND version=$3 AND run_id=$4 AND sequence>$6`, now, id, task.TargetVersion, task.RunID, first+22, first)
	f.exec(`UPDATE v2_dispatch_monitor_state SET reported_at=$1 WHERE monitor_id=$2 AND probe_id=$3`, now, id, f.pid)
	states, err := dispatchSplitStates(f.ctx, f.db)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, c := range states {
		if c.Host == host && c.ProbeID == f.pid {
			return c
		}
	}
	f.t.Fatal("missing timeout state")
	return dispatchSplitCandidate{}
}
func (f *splitIntegration) view() DispatchAutoSplitView {
	f.t.Helper()
	v, err := f.s.GetDispatchAutoSplit(f.ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	return v
}

func (f *splitIntegration) confirmedTimeout(host string) dispatchSplitCandidate {
	f.t.Helper()
	c := f.timeout(host)
	// Simulate a successful first sample followed by over ten minutes of timeout.
	f.exec(`UPDATE v2_dispatch_history SET success=TRUE,payload=jsonb_set(jsonb_set(payload,'{success}','true'::jsonb),'{error}','""'::jsonb) WHERE target_id=$1 AND source='entry' AND version=$2 AND run_id=$3 AND sequence=(SELECT min(sequence) FROM v2_dispatch_history WHERE target_id=$1 AND source='entry' AND version=$2 AND run_id=$3)`, c.ID, c.Version, c.RunID)
	return c
}
func (f *splitIntegration) process(c dispatchSplitCandidate) bool {
	f.t.Helper()
	changed, err := f.s.processDispatchAutoSplit(f.ctx, c)
	if err != nil {
		f.t.Fatal(err)
	}
	return changed
}
func (f *splitIntegration) successes() int {
	f.t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_auto_split_operation WHERE status='succeeded'`).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func TestPostgresDispatchAutoSplitAtomicityAndStableFamily(t *testing.T) {
	f := newSplitIntegration(t)
	f.pool("192.0.2.101", "192.0.2.102", "192.0.2.103", "192.0.2.104", "192.0.2.105", "192.0.2.106")
	c := f.timeout("range.example")
	if f.process(c) {
		t.Fatal("default-off changed subscriptions")
	}
	f.enable()
	if !f.process(c) {
		t.Fatalf("split failed: %#v", f.view())
	}
	v := f.view()
	if len(v.Operations) != 1 {
		t.Fatal(v)
	}
	op := v.Operations[0]
	if op.RangeA != "10-55" || op.RangeB != "56-100" || op.IPA == op.IPB || op.ChildAID == op.ChildBID || op.GroupID != op.RootGroupID || op.ChildAID == 0 {
		t.Fatalf("invalid groups: %#v", op)
	}
	if f.process(c) || f.successes() != 1 {
		t.Fatal("same incident executed twice")
	}
	// Actual subscription selectors read these modified rules; verify every ID
	// and preserve all other catalog ownership, rather than only checking logs.
	entries, err := usersvc.DispatchEntriesFrom(f.ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	byHost := map[string]usersvc.DispatchEntry{}
	for _, e := range entries {
		byHost[e.Host] = e
	}
	if _, ok := byHost["range.example"]; ok {
		t.Fatal("old host still dispatched")
	}
	if fmt.Sprint(byHost[op.IPA].UserIDRanges) != "[10-55]" || fmt.Sprint(byHost[op.IPB].UserIDRanges) != "[56-100]" {
		t.Fatal(byHost)
	}
	var ports string
	if err = f.db.QueryRow(`SELECT port FROM v2_server_vmess WHERE id=7`).Scan(&ports); err != nil || ports != "443" {
		t.Fatal("subscription port changed", ports, err)
	}
	ca := f.confirmedTimeout(op.IPA)
	cb := f.confirmedTimeout(op.IPB)
	if f.process(ca) || f.process(cb) || f.successes() != 1 {
		t.Fatal("new IP or ID range bypassed inherited cooldown")
	}
	for _, x := range f.view().Operations {
		if x.RootGroupID != op.RootGroupID {
			t.Fatalf("descendant got a different root: %#v", x)
		}
	}
	// A separately initialized service reads durable limits; it must not invent
	// new group identities from current host or range.
	restarted := NewDBService(config.Config{}, f.db)
	changed, err := restarted.processDispatchAutoSplit(f.ctx, ca)
	if err != nil || changed {
		t.Fatal("restart bypassed root quota", changed, err)
	}
	// Release only the root cooldown, preserving real ten-minute child evidence.
	f.exec(`UPDATE v2_dispatch_auto_split_operation SET updated_at=$1 WHERE status='succeeded'`, time.Now().Unix()-1201)
	f.exec(`UPDATE v2_dispatch_auto_split_cooldown SET last_success_at=$1`, time.Now().Unix()-1201)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	changes := make(chan bool, 2)
	for _, candidate := range []dispatchSplitCandidate{ca, cb} {
		wg.Add(1)
		go func(c dispatchSplitCandidate) {
			defer wg.Done()
			changed, e := f.s.processDispatchAutoSplit(f.ctx, c)
			errs <- e
			changes <- changed
		}(candidate)
	}
	wg.Wait()
	close(errs)
	close(changes)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	n := 0
	for changed := range changes {
		if changed {
			n++
		}
	}
	if n != 1 || f.successes() != 2 {
		t.Fatalf("siblings consumed more than one family slot: %d", n)
	}
	v = f.view()
	for _, x := range v.Operations {
		if x.RootGroupID != op.RootGroupID {
			t.Fatal("grandchild lost root identity", x)
		}
	}
	// Changing settings cancels observations, never erases successful quota.
	if err = f.s.SaveDispatchAutoSplit(f.ctx, DispatchAutoSplitSettings{EntryWindowMinutes: 20, GlobalWindowMinutes: 60, GlobalMax: 3}); err != nil {
		t.Fatal(err)
	}
	if f.successes() != 2 {
		t.Fatal("settings erased successful ledger")
	}
}

func TestPostgresDispatchAutoSplitShortageAndGlobalQuota(t *testing.T) {
	f := newSplitIntegration(t)
	f.enable()
	f.pool("192.0.2.111")
	c := f.timeout("range.example")
	before := f.snapshot("v2_node_address_rule", "v2_dispatch_monitor", "v2_dispatch_monitor_probe")
	if f.process(c) || f.successes() != 0 || !strings.Contains(f.view().Operations[0].Reason, "不足两个") {
		t.Fatal("shortage should wait without consuming an IP", f.view())
	}
	if fmt.Sprint(before) != fmt.Sprint(f.snapshot("v2_node_address_rule", "v2_dispatch_monitor", "v2_dispatch_monitor_probe")) {
		t.Fatal("shortage partially modified configuration")
	}
	f.pool("192.0.2.112", "192.0.2.113")
	// Add three successful operations for unrelated stable families in the last
	// hour. Host names and ranges deliberately differ from the pending entry.
	for i := 1; i <= 3; i++ {
		f.exec(`INSERT INTO v2_dispatch_auto_split_operation(monitor_id,version,probe_id,run_id,host,root_host,group_id,root_group_id,status,created_at,updated_at) VALUES($1,1,1,1,'unrelated','unrelated',$1,$1,'succeeded',$2,$2)`, -i, time.Now().Unix()-60)
	}
	if f.process(c) || !strings.Contains(f.view().Operations[0].Reason, "全局") {
		t.Fatal("global rolling cap bypassed", f.view())
	}
	f.exec(`UPDATE v2_dispatch_auto_split_operation SET updated_at=$1 WHERE monitor_id=-1`, time.Now().Unix()-3601)
	if !f.process(c) || f.successes() != 4 {
		t.Fatal("window failed to release", f.view())
	}
}

func TestDispatchAutoSplitInvalidSettings(t *testing.T) {
	s := &DBService{}
	for _, v := range []DispatchAutoSplitSettings{{EntryWindowMinutes: 0, GlobalWindowMinutes: 60, GlobalMax: 3}, {EntryWindowMinutes: 20, GlobalWindowMinutes: 10081, GlobalMax: 3}, {EntryWindowMinutes: 20, GlobalWindowMinutes: 60, GlobalMax: 101}} {
		if err := s.SaveDispatchAutoSplit(context.Background(), v); err == nil {
			t.Fatal("invalid frequency accepted")
		}
	}
}

func TestPostgresDispatchAutoSplitWorkerRevalidatesAndCancels(t *testing.T) {
	f := newSplitIntegration(t)
	f.enable()
	f.pool("192.0.2.121")
	c := f.timeout("range.example")
	if err := f.s.runDispatchAutoSplitCycle(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.successes() != 0 || len(f.view().Operations) != 1 {
		t.Fatal("worker failed to persist shortage", f.view())
	}
	// A healthy peer must belong to the same probe and current actual catalog.
	f.exec(`UPDATE v2_dispatch_monitor_state SET success=FALSE,error='connect_error' WHERE monitor_id<>$1`, c.ID)
	f.pool("192.0.2.122")
	if f.process(c) {
		t.Fatal("split despite no healthy same-probe peer")
	}
	// A recovery retires the pending observation on the next worker tick.
	f.exec(`UPDATE v2_dispatch_monitor_state SET success=TRUE,error='',latency_ms=12 WHERE monitor_id=$1`, c.ID)
	if err := f.s.runDispatchAutoSplitCycle(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.view().Operations[0].Status != "cancelled" {
		t.Fatal("recovered observation stayed pending", f.view())
	}
}

func TestPostgresDispatchAutoSplitInsiderPriorityRollback(t *testing.T) {
	for _, overlap := range []bool{false, true} {
		t.Run(fmt.Sprint(overlap), func(t *testing.T) {
			f := newSplitIntegration(t)
			f.exec(`INSERT INTO v2_insider_rule(name,host,match_user_id_ranges,enabled,created_at,updated_at) VALUES('split original','inside-range.example','["10-100"]',1,1,1)`)
			if overlap {
				f.exec(`INSERT INTO v2_insider_rule(name,host,match_user_id_ranges,enabled,created_at,updated_at) VALUES('lower priority','other.example','["40-100"]',1,1,1)`)
			}
			f.save("inside-range.example", f.pid)
			f.enable()
			f.pool("192.0.2.131", "192.0.2.132")
			c := f.timeout("inside-range.example")
			before := f.snapshot("v2_insider_rule", "v2_dispatch_monitor", "v2_dispatch_monitor_probe")
			changed := f.process(c)
			if !overlap && !changed {
				t.Fatal("single insider range did not split", f.view())
			}
			if overlap && (changed || fmt.Sprint(before) != fmt.Sprint(f.snapshot("v2_insider_rule", "v2_dispatch_monitor", "v2_dispatch_monitor_probe"))) {
				t.Fatal("priority conflict partially rewrote live addresses", f.view())
			}
		})
	}
}

func TestPostgresDispatchAutoSplitNodeFallback(t *testing.T) {
	f := newSplitIntegration(t)
	f.exec(`DELETE FROM v2_node_address_binding; INSERT INTO v2_insider_rule(name,host,match_user_id_ranges,enabled,created_at,updated_at) VALUES('other ranges','guard.example','["1-9","101-9223372036854775807"]',1,1,1)`)
	// Shared fixture inserted group #1 explicitly; advance its identity before
	// exercising creation of a genuinely new group.
	f.exec(`SELECT setval(pg_get_serial_sequence('v2_node_address_group','id'),(SELECT max(id) FROM v2_node_address_group))`)
	f.save("guard.example", f.pid)
	f.s.dispatchCacheMu.Lock()
	f.s.dispatchCachedHosts = nil
	f.s.dispatchCacheAt = time.Time{}
	f.s.dispatchCacheMu.Unlock()
	f.report(f.pid, f.tasks(f.pid)["guard.example"], 1, 1, 0)
	f.enable()
	f.pool("192.0.2.141", "192.0.2.142")
	c := f.timeout("base.example")
	if !f.process(c) {
		t.Fatal("node fallback did not split", f.view())
	}
	var host, port string
	if err := f.db.QueryRow(`SELECT host,port FROM v2_server_vmess WHERE id=7`).Scan(&host, &port); err != nil || host != "base.example" || port != "443" {
		t.Fatal("node base address or subscription port rewritten", host, port, err)
	}
	var rules int
	if err := f.db.QueryRow(`SELECT count(*) FROM v2_node_address_rule r JOIN v2_node_address_binding b ON b.address_group_id=r.group_id WHERE b.server_type='vmess' AND b.server_id=7`).Scan(&rules); err != nil || rules != 2 {
		t.Fatal("expected two scoped node-address rules", rules, err)
	}
}
