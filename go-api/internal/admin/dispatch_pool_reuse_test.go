package admin

import (
	"database/sql"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func poolReuseOldMonitor(f *splitIntegration, host string, enabled, deleted bool) int64 {
	f.t.Helper()
	var id int64
	if err := f.db.QueryRow(`INSERT INTO v2_dispatch_monitor(host,check_port,enabled,deleted,check_interval_sec,tcp_timeout_ms,version) VALUES($1,443,$2,$3,10,1000,7) RETURNING id`, host, enabled, deleted).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	f.exec(`INSERT INTO v2_dispatch_monitor_probe(monitor_id,probe_id,run_id) VALUES($1,$2,4)`, id, f.pid)
	f.exec(`INSERT INTO v2_dispatch_monitor_state(monitor_id,probe_id,version,sequence,success,error,reported_at) VALUES($1,$2,7,99,FALSE,'timeout',$3)`, id, f.pid, time.Now().Unix())
	f.exec(`INSERT INTO v2_dispatch_history(source,target_id,probe_id,version,run_id,sequence,kind,host,port,success,payload,created_at) VALUES('entry',$1,$2,7,4,99,'sample',$3,443,FALSE,'{}',$4)`, id, f.pid, host, time.Now().Unix())
	return id
}

func poolReuseTx(f *splitIntegration) *sql.Tx {
	f.t.Helper()
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { tx.Rollback() })
	if _, err = tx.ExecContext(f.ctx, `SELECT pg_advisory_xact_lock(7642309023)`); err != nil {
		f.t.Fatal(err)
	}
	if err = lockInvestigationAddresses(f.ctx, tx); err != nil {
		f.t.Fatal(err)
	}
	return tx
}

func TestPostgresDispatchPoolReusesUnreferencedMonitorWithFreshIdentity(t *testing.T) {
	for _, tc := range []struct {
		name             string
		enabled, deleted bool
	}{{"deleted", false, true}, {"disabled", false, false}, {"orphan enabled", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSplitIntegration(t)
			const ip = "192.0.2.201"
			f.pool(ip)
			old := poolReuseOldMonitor(f, ip, tc.enabled, tc.deleted)
			// A historical split family must stay attached to the old identity.
			f.exec(`INSERT INTO v2_dispatch_auto_split_group(monitor_id,host,id_range,created_at) VALUES($1,$2,'10-100',1)`, old, ip)
			items, err := f.s.ListDispatchPool(f.ctx)
			if err != nil || len(items) != 1 || !items[0].Available || items[0].Used {
				t.Fatal("orphan monitor reserved pool IP", items, err)
			}
			source := -f.tasks(f.pid)["range.example"].TargetID
			tx := poolReuseTx(f)
			refs, err := dispatchPoolReferences(f.ctx, tx)
			if err != nil {
				t.Fatal(err)
			}
			pool, err := f.s.dispatchSplitPoolLimit(f.ctx, tx, refs, dispatchSplitCandidate{ID: source}, false, nil, 1)
			if err != nil || len(pool) != 1 || pool[0].IP != ip {
				t.Fatal(pool, err)
			}
			id, err := cloneDispatchPoolMonitor(f.ctx, tx, source, ip)
			if err != nil || id == old {
				t.Fatal("failed to create a fresh monitor", id, old, err)
			}
			locked, err := f.s.dispatchSplitPoolLimit(f.ctx, tx, refs, dispatchSplitCandidate{ID: source}, true, pool, 1)
			if err != nil || len(locked) != 1 {
				t.Fatal("post-clone health check disagreed", locked, err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			var port, version, states, bindings, history int64
			if err = f.db.QueryRow(`SELECT check_port,version,(SELECT count(*) FROM v2_dispatch_monitor_state WHERE monitor_id=$1) FROM v2_dispatch_monitor WHERE id=$1 AND host=$2 AND enabled AND NOT deleted`, id, ip).Scan(&port, &version, &states); err != nil || port != 18443 || version != 1 || states != 0 {
				t.Fatal("inherited stale state or wrong port", port, version, states, err)
			}
			var archived bool
			if err = f.db.QueryRow(`SELECT deleted AND NOT enabled AND host<>$2 FROM v2_dispatch_monitor WHERE id=$1`, old, ip).Scan(&archived); err != nil || !archived {
				t.Fatal("old monitor not retired", err)
			}
			if err = f.db.QueryRow(`SELECT (SELECT count(*) FROM v2_dispatch_monitor_probe WHERE monitor_id=$1),(SELECT count(*) FROM v2_dispatch_history WHERE target_id=$1 AND source='entry' AND host=$2)`, old, ip).Scan(&bindings, &history); err != nil || bindings != 0 || history != 1 {
				t.Fatal("history lost or stale bindings survived", bindings, history, err)
			}
			yes, latency := true, int64(12)
			report, err := f.s.ReportDispatchProbeResults(f.ctx, f.pid, DNSProbeResultsRequest{Results: []DNSProbeResult{{ResultID: "late-100", TargetID: -old, TargetVersion: 7, RunID: 4, Success: &yes, LatencyMS: &latency}}})
			if err != nil || report.Accepted != 0 || report.Skipped != 1 {
				t.Fatal("old report accepted", report, err)
			}
			groups, err := readDispatchSplitGroups(f.ctx, f.db)
			if err != nil || len(groups) != 1 || groups[0].MonitorID != old || groups[0].Active {
				t.Fatal("historical lineage rebound to fresh monitor", groups, err)
			}
		})
	}
}

func TestPostgresDispatchPoolReuseKeepsConfigurationReservations(t *testing.T) {
	f := newSplitIntegration(t)
	f.pool("192.0.2.201", "192.0.2.202", "192.0.2.203")
	for _, ip := range []string{"192.0.2.201", "192.0.2.202", "192.0.2.203"} {
		poolReuseOldMonitor(f, ip, false, true)
	}
	// A disabled fallback and a range for future accounts are intentional leases.
	f.exec(`INSERT INTO v2_insider_rule(host,match_user_ids,enabled,created_at,updated_at) VALUES('192.0.2.201','["42"]',0,1,1)`)
	f.exec(`INSERT INTO v2_node_address_rule(group_id,host,match_user_id_ranges,created_at,updated_at) VALUES(1,'192.0.2.202','["900001-900010"]',1,1)`)
	source := -f.tasks(f.pid)["range.example"].TargetID
	before := f.snapshot("v2_dispatch_monitor", "v2_dispatch_monitor_probe", "v2_dispatch_history")
	tx := poolReuseTx(f)
	refs, err := dispatchPoolReferences(f.ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := f.s.dispatchSplitPoolLimit(f.ctx, tx, refs, dispatchSplitCandidate{ID: source}, false, nil, 3)
	if err != nil || len(pool) != 1 || pool[0].IP != "192.0.2.203" {
		t.Fatal("fallback or future range released", pool, err)
	}
	for _, ip := range []string{"192.0.2.201", "192.0.2.202"} {
		if _, err = cloneDispatchPoolMonitor(f.ctx, tx, source, ip); err == nil {
			t.Fatal("referenced host recycled", ip)
		}
	}
	if _, err = cloneDispatchPoolMonitor(f.ctx, tx, source, "192.0.2.203"); err != nil {
		t.Fatal(err)
	}
	// A failed enclosing allocation must restore the monitor, bindings and audit.
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, f.snapshot("v2_dispatch_monitor", "v2_dispatch_monitor_probe", "v2_dispatch_history")) {
		t.Fatal("rollback did not restore old resources")
	}
}

func TestPostgresDispatchPoolReusePrefersUnusedEntrances(t *testing.T) {
	f := newSplitIntegration(t)
	f.pool("192.0.2.201", "192.0.2.202")
	poolReuseOldMonitor(f, "192.0.2.201", false, true)
	source := -f.tasks(f.pid)["range.example"].TargetID
	tx := poolReuseTx(f)
	refs, err := dispatchPoolReferences(f.ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	selectIP := func(want string) {
		t.Helper()
		pool, err := f.s.dispatchSplitPoolLimit(f.ctx, tx, refs, dispatchSplitCandidate{ID: source}, false, nil, 1)
		if err != nil || len(pool) != 1 || pool[0].IP != want {
			t.Fatal("unexpected pool preference", pool, want, err)
		}
	}
	selectIP("192.0.2.202")
	if _, err = tx.ExecContext(f.ctx, `UPDATE v2_dispatch_check_target SET sort=1 WHERE kind='pool' AND host='192.0.2.202'`); err != nil {
		t.Fatal(err)
	}
	selectIP("192.0.2.201") // An explicit operator priority still takes precedence.
	if _, err = tx.ExecContext(f.ctx, `UPDATE v2_dispatch_check_target SET sort=0 WHERE kind='pool'`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(f.ctx, `UPDATE v2_dispatch_check_target SET enabled=FALSE WHERE kind='pool' AND host='192.0.2.202'`); err != nil {
		t.Fatal(err)
	}
	selectIP("192.0.2.201") // Old monitor no longer makes the fallback unusable.
}

func TestPostgresDispatchPoolReuseAutomaticSplitEndToEnd(t *testing.T) {
	f := newSplitIntegration(t)
	f.pool("192.0.2.201", "192.0.2.202")
	oldA := poolReuseOldMonitor(f, "192.0.2.201", false, true)
	oldB := poolReuseOldMonitor(f, "192.0.2.202", true, false)
	f.enable()
	if !f.process(f.timeout("range.example")) {
		t.Fatal("split stayed blocked", f.view())
	}
	op := f.view().Operations[0]
	if op.IPA != "192.0.2.201" || op.IPB != "192.0.2.202" {
		t.Fatal(op)
	}
	for _, g := range splitTestGroups(f) {
		if g.ID == op.ChildAID || g.ID == op.ChildBID {
			if g.MonitorID == oldA || g.MonitorID == oldB {
				t.Fatal("reused historical identity", g)
			}
		}
	}
	if f.successes() != 1 {
		t.Fatal("duplicate allocation")
	}
}

func TestPostgresDispatchPoolReuseInvestigationEndToEnd(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.201", "192.0.2.202")
	f.exec(`UPDATE v2_dispatch_monitor SET check_port=42822 WHERE host='range.example'`)
	f.exec(`UPDATE v2_dispatch_check_target SET port=42822 WHERE kind='pool'`)
	old := map[int64]bool{poolReuseOldMonitor(f.splitIntegration, "192.0.2.201", false, true): true, poolReuseOldMonitor(f.splitIntegration, "192.0.2.202", true, false): true}
	g := f.group("range.example")
	f.outage(g, investigationGroupIDs(g))
	f.execProcess(g.ID)
	if f.successfulEvents() != 1 {
		t.Fatal("investigation stayed blocked", f.groups())
	}
	children := 0
	for _, child := range f.groups() {
		if child.ParentID != g.ID {
			continue
		}
		children++
		if old[child.MonitorID] || child.ReadyAt != 0 {
			t.Fatal("old incident inherited", child)
		}
		var port int64
		if err := f.db.QueryRow(`SELECT check_port FROM v2_dispatch_monitor WHERE id=$1`, child.MonitorID).Scan(&port); err != nil || port != 42822 {
			t.Fatal(port, err)
		}
	}
	if children != 2 {
		t.Fatal(fmt.Sprint(f.groups()))
	}
}
