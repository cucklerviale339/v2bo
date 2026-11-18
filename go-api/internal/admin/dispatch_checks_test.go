package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"forest/go-api/internal/config"
	"forest/go-api/internal/platform/postgres"
	usersvc "forest/go-api/internal/user"
)

func TestDispatchPoolHealthRequiresEveryOnlineProbeAndTwoSuccesses(t *testing.T) {
	yes, no := true, false
	healthy := DispatchCheckState{DispatchMonitorState: DispatchMonitorState{Online: true, Success: &yes}, ConsecutiveSuccess: 2}
	cases := []struct {
		name      string
		item      DispatchPoolItem
		status    string
		available bool
	}{
		{"no probes", DispatchPoolItem{DispatchPoolSave: DispatchPoolSave{Enabled: true}}, "no_probe", false},
		{"offline ignored", DispatchPoolItem{DispatchPoolSave: DispatchPoolSave{Enabled: true}, States: []DispatchCheckState{healthy, {DispatchMonitorState: DispatchMonitorState{Online: false}}}}, "available", true},
		{"missing result", DispatchPoolItem{DispatchPoolSave: DispatchPoolSave{Enabled: true}, States: []DispatchCheckState{healthy, {DispatchMonitorState: DispatchMonitorState{Online: true, Stale: true}}}}, "checking", false},
		{"single success", DispatchPoolItem{DispatchPoolSave: DispatchPoolSave{Enabled: true}, States: []DispatchCheckState{{DispatchMonitorState: DispatchMonitorState{Online: true, Success: &yes}, ConsecutiveSuccess: 1}}}, "checking", false},
		{"any failed", DispatchPoolItem{DispatchPoolSave: DispatchPoolSave{Enabled: true}, States: []DispatchCheckState{healthy, {DispatchMonitorState: DispatchMonitorState{Online: true, Success: &no}}}}, "unhealthy", false},
		{"reference", DispatchPoolItem{DispatchPoolSave: DispatchPoolSave{Enabled: true}, Used: true, States: []DispatchCheckState{healthy}}, "in_use", false},
		{"disabled", DispatchPoolItem{States: []DispatchCheckState{healthy}}, "disabled", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, available := classifyDispatchPool(c.item)
			if status != c.status || available != c.available {
				t.Fatalf("%s %v", status, available)
			}
		})
	}
	for _, ip := range []string{"example.com", "http://192.0.2.1", "fe80::1%eth0"} {
		x := DispatchPoolSave{IP: ip, Port: 443, CheckIntervalSec: 30, TCPTimeoutMS: 3000}
		if !errors.Is(normalizeDispatchPool(&x), ErrDNSProbeInvalidRequest) {
			t.Fatal(ip)
		}
	}
	x := DispatchPoolSave{IP: "::ffff:192.0.2.1", Port: 443, CheckIntervalSec: 30, TCPTimeoutMS: 3000}
	if err := normalizeDispatchPool(&x); err != nil || x.IP != "192.0.2.1" {
		t.Fatalf("%#v %v", x, err)
	}
}

func TestPostgresDispatchPoolAndRunLifecycle(t *testing.T) {
	dsn := os.Getenv("DNS_FAILOVER_TEST_DSN")
	if dsn == "" {
		t.Skip("DNS_FAILOVER_TEST_DSN not set")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("test DSN must be postgres URL")
	}
	root, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	schema := fmt.Sprintf("dispatch_checks_%d", time.Now().UnixNano())
	if _, err = root.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	defer root.Exec("DROP SCHEMA " + schema + " CASCADE")
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	db, err := sql.Open("pgx", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, kind := range []string{"shadowsocks", "vmess", "trojan", "tuic", "hysteria", "vless", "anytls", "v2node"} {
		exec("CREATE TABLE v2_server_" + kind + `(id BIGINT PRIMARY KEY,host TEXT,"show" SMALLINT NOT NULL DEFAULT 1)`)
	}
	if err = postgres.EnsureNodeAddressSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	// Disabled and conditional references count as config reservations, while
	// manual entry checks require an actual recipient.
	exec(`CREATE TABLE v2_user(id BIGINT PRIMARY KEY); INSERT INTO v2_user(id) VALUES(42),(99)`)
	exec(`INSERT INTO v2_server_vmess(id,host) VALUES(7,'192.0.2.7(plan=x),192.0.2.8');
 INSERT INTO v2_insider_rule(host,match_user_ids,enabled,created_at,updated_at) VALUES('192.0.2.9','["42"]',0,1,1)`)
	s := NewDBService(config.Config{}, db)
	catalog := &testDispatchCatalog{entries: []usersvc.DispatchEntry{{Host: "192.0.2.7", UserIDs: []string{"42"}, UserIDRanges: []string{"100-200"}, Sources: []string{"节点管理 vmess #7"}}}}
	s.dispatchCatalog = catalog
	if err = s.ensureDispatchMonitorSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err = NewDBService(config.Config{}, db).ensureDispatchMonitorSchema(ctx); err != nil {
		t.Fatal("idempotent upgrade", err)
	}
	makePool := func(ip string, port int64) DispatchPoolSave {
		return DispatchPoolSave{IP: ip, Port: port, Enabled: true, CheckIntervalSec: 5, TCPTimeoutMS: 500}
	}
	ids, err := s.SaveDispatchPool(ctx, []DispatchPoolSave{makePool("192.0.2.7", 443), makePool("192.0.2.10", 443), makePool("192.0.2.10", 8443), makePool("192.0.2.9", 443)})
	if err != nil || len(ids) != 4 {
		t.Fatal(ids, err)
	}
	if _, err = s.SaveDispatchPool(ctx, []DispatchPoolSave{makePool("192.0.2.11", 443), makePool("192.0.2.10", 443)}); !errors.Is(err, ErrDNSProbeInvalidRequest) {
		t.Fatal("duplicate accepted", err)
	}
	pool, err := s.ListDispatchPool(ctx)
	if err != nil || len(pool) != 4 || !pool[0].Used || !reflect.DeepEqual(pool[0].Ownership.UserIDs, []string{"42"}) || !pool[3].Used {
		t.Fatalf("pool=%#v err=%v", pool, err)
	}
	if _, err = s.DeleteDispatchPool(ctx, []int64{ids[0]}); !errors.Is(err, ErrDNSProbeInvalidRequest) {
		t.Fatal("referenced resource deleted", err)
	}
	p1, err := s.CreateDNSProbe(ctx, DNSProbeCreateRequest{Name: "one"})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := s.CreateDNSProbe(ctx, DNSProbeCreateRequest{Name: "two"})
	if err != nil {
		t.Fatal(err)
	}
	pid1, pid2 := p1.Probe.ID, p2.Probe.ID
	heartbeat := func(pid int64) {
		t.Helper()
		if _, err := s.HeartbeatDNSProbe(ctx, pid, DNSProbeHeartbeatRequest{Version: "checks-test", Arch: "amd64", PublicIP: "192.0.2.1"}); err != nil {
			t.Fatal(err)
		}
	}
	heartbeat(pid1)
	heartbeat(pid2)
	tasks, err := s.ListDispatchCheckTasks(ctx, pid1)
	if err != nil || len(tasks) != 4 {
		t.Fatal(tasks, err)
	}
	poolTask := func(pid, id int64) DNSProbeTask {
		t.Helper()
		tasks, err := s.ListDispatchCheckTasks(ctx, pid)
		if err != nil {
			t.Fatal(err)
		}
		for _, task := range tasks {
			if task.TargetID == -(dispatchCheckOffset + id) {
				return task
			}
		}
		t.Fatal("task missing", id)
		return DNSProbeTask{}
	}
	yes, no := true, false
	result := func(task DNSProbeTask, seq int64, success *bool) DNSProbeResult {
		latency := int64(12)
		r := DNSProbeResult{TargetID: task.TargetID, TargetVersion: task.TargetVersion, RunID: task.RunID, ResultID: fmt.Sprintf("%d-%d", task.TargetID, seq), Success: success, ResolvedIP: "192.0.2.10"}
		if *success {
			r.LatencyMS = &latency
		} else {
			r.Error = "timeout"
		}
		return r
	}
	report := func(pid int64, r DNSProbeResult) DNSProbeReportResult {
		t.Helper()
		v, err := s.ReportDispatchCheckResults(ctx, pid, DNSProbeResultsRequest{Results: []DNSProbeResult{r}})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	task := poolTask(pid1, ids[1])
	report(pid1, result(task, 100, &yes))
	report(pid1, result(task, 101, &yes))
	pool, _ = s.ListDispatchPool(ctx)
	if pool[1].Available {
		t.Fatal("missing second probe considered healthy")
	}
	task2 := poolTask(pid2, ids[1])
	report(pid2, result(task2, 100, &yes))
	report(pid2, result(task2, 101, &yes))
	pool, _ = s.ListDispatchPool(ctx)
	if !pool[1].Available {
		t.Fatal("both healthy not available", pool[1])
	}
	if r := report(pid1, result(task, 99, &no)); r.Duplicates != 1 {
		t.Fatal("out of order accepted", r)
	}
	if err = s.RefreshDispatchPool(ctx, []int64{ids[1]}); err != nil {
		t.Fatal(err)
	}
	if r := report(pid1, result(task, 102, &yes)); r.Skipped != 1 {
		t.Fatal("old generation accepted", r)
	}
	task = poolTask(pid1, ids[1])
	report(pid1, result(task, 103, &yes))
	report(pid1, result(task, 104, &yes))
	// A queued pre-disconnect report cannot revive a fresh pool state.
	exec(`UPDATE v2_dns_probe SET last_heartbeat_at=$2 WHERE id=$1`, pid1, time.Now().Unix()-100)
	heartbeat(pid1)
	if r := report(pid1, result(task, 105, &yes)); r.Skipped != 1 {
		t.Fatal("old session revived", r)
	}
	task = poolTask(pid1, ids[1])
	report(pid1, result(task, 106, &yes))
	pool, _ = s.ListDispatchPool(ctx)
	if pool[1].Available {
		t.Fatal("single success passed warmup")
	}
	// Each port has its own state; a healthy 443 does not make 8443 healthy.
	report(pid1, result(task, 107, &yes))
	task2 = poolTask(pid2, ids[1])
	report(pid2, result(task2, 103, &yes))
	report(pid2, result(task2, 104, &yes))
	pool, _ = s.ListDispatchPool(ctx)
	if !pool[1].Available || pool[2].Available {
		t.Fatal("port state leaked", pool)
	}
	// Editing a custom port invalidates both the generation and warmup state.
	edited := makePool("192.0.2.10", 9443)
	edited.ID = ids[2]
	oldPortTask := poolTask(pid1, ids[2])
	if _, err = s.SaveDispatchPool(ctx, []DispatchPoolSave{edited}); err != nil {
		t.Fatal(err)
	}
	if r := report(pid1, result(oldPortTask, 108, &yes)); r.Skipped != 1 {
		t.Fatal("queued old port accepted", r)
	}
	if updated := poolTask(pid1, ids[2]); updated.CheckPort != 9443 {
		t.Fatal("port edit not scheduled", updated)
	}
	if err = s.SaveDispatchMonitor(ctx, DispatchMonitorSaveRequest{Host: "192.0.2.7", CheckPort: 1443, Enabled: true, CheckIntervalSec: 5, TCPTimeoutMS: 500, ProbeIDs: []int64{pid1, pid2}}); err != nil {
		t.Fatal(err)
	}
	runID, err := s.StartDispatchRun(ctx, DispatchRunRequest{Hosts: []string{"192.0.2.7"}})
	if err != nil {
		t.Fatal(err)
	}
	runs, total, err := s.ListDispatchRuns(ctx, 1)
	if err != nil || total != 1 || runs[0].Expected != 2 || runs[0].Received != 0 {
		t.Fatal(runs, total, err)
	}
	getRunTask := func(pid int64) DNSProbeTask {
		t.Helper()
		tasks, err := s.ListDispatchCheckTasks(ctx, pid)
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range tasks {
			if x.CheckPort == 1443 && x.TargetID <= -dispatchCheckOffset {
				return x
			}
		}
		t.Fatal("no run task")
		return DNSProbeTask{}
	}
	run1, run2 := getRunTask(pid1), getRunTask(pid2)
	catalog.entries[0].UserIDs = []string{"99"}
	catalog.entries[0].Sources = []string{"changed"}
	// Two probes reporting at once must complete the same run reliably.
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, pair := range []struct {
		pid     int64
		task    DNSProbeTask
		success *bool
	}{{pid1, run1, &yes}, {pid2, run2, &no}} {
		wg.Add(1)
		go func(pid int64, task DNSProbeTask, success *bool) {
			defer wg.Done()
			_, err := s.ReportDispatchCheckResults(ctx, pid, DNSProbeResultsRequest{Results: []DNSProbeResult{result(task, 200, success)}})
			errs <- err
		}(pair.pid, pair.task, pair.success)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	runs, _, _ = s.ListDispatchRuns(ctx, 1)
	if runs[0].Status != "completed" || runs[0].Received != 2 || runs[0].Failed != 1 {
		t.Fatal(runs)
	}
	details, n, err := s.DispatchRunResults(ctx, runID, 1)
	if err != nil || n != 2 || details[0].Success == nil || *details[0].Success || !reflect.DeepEqual(details[0].Ownership.UserIDs, []string{"42"}) || details[0].Port != 1443 {
		t.Fatal("snapshot changed", details, n, err)
	}
	// Manual run never wrote continuous monitor health.
	current, err := s.ListDispatchMonitors(ctx)
	if err != nil || len(current) != 1 || len(current[0].States) == 0 || current[0].States[0].Success != nil {
		t.Fatal("manual check overwrote continuous state", current, err)
	}
	heartbeat(pid1)
	details, _, _ = s.DispatchRunResults(ctx, runID, 1)
	if details[1].Success == nil {
		t.Fatal("heartbeat cleared history")
	}
	// Delete a probe: its historical report and expected-pair identity survive.
	exec(`DELETE FROM v2_dns_probe WHERE id=$1`, pid2)
	details, n, _ = s.DispatchRunResults(ctx, runID, 1)
	if n != 2 || details[0].ProbeName != "two" {
		t.Fatal("probe deletion lost history", details)
	}
	pending, err := s.StartDispatchRun(ctx, DispatchRunRequest{PoolIDs: []int64{ids[1]}})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := s.ClearDispatchRuns(ctx); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	exec(`UPDATE v2_dispatch_check_run SET deadline_at=$2 WHERE id=$1`, pending, time.Now().Unix()-1)
	runs, _, err = s.ListDispatchRuns(ctx, 1)
	if err != nil || len(runs) != 1 || runs[0].Status != "timeout" {
		t.Fatal(runs, err)
	}
	if _, err = s.StartDispatchRun(ctx, DispatchRunRequest{Hosts: []string{"removed.example"}}); !errors.Is(err, ErrDNSProbeInvalidRequest) {
		t.Fatal("unknown target accepted", err)
	}
	// Paging returns all 101 expected pairs, including missing reports.
	exec(`INSERT INTO v2_dispatch_check_binding(target_id,probe_id,probe_name)
 SELECT t.id,1000+n,'archived-probe-'||n FROM v2_dispatch_check_target t CROSS JOIN generate_series(1,100) n WHERE t.run_id=$1`, pending)
	details, n, err = s.DispatchRunResults(ctx, pending, 1)
	if err != nil || len(details) != 100 || n != 101 {
		t.Fatal("paging first", len(details), n, err)
	}
	details, n, err = s.DispatchRunResults(ctx, pending, 2)
	if err != nil || len(details) != 1 || n != 101 {
		t.Fatal("paging second", len(details), n, err)
	}
	exec(`UPDATE v2_dispatch_check_run SET created_at=$2 WHERE id=$1`, pending, time.Now().Unix()-8*86400)
	if _, n, err = s.ListDispatchRuns(ctx, 1); err != nil || n != 0 {
		t.Fatal("retention", n, err)
	}
	if n, err = s.DeleteDispatchPool(ctx, []int64{ids[1], ids[2]}); err != nil || n != 2 {
		t.Fatal("delete unused", n, err)
	}
	// Server-side fault deletion rechecks health and references, independently
	// of what a client observed before clicking confirmation.
	cleanupIDs, err := s.SaveDispatchPool(ctx, []DispatchPoolSave{makePool("192.0.2.20", 443), makePool("192.0.2.21", 443), makePool("192.0.2.22", 443), makePool("192.0.2.23", 443), makePool("192.0.2.7", 9443)})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range cleanupIDs {
		task := poolTask(pid1, id)
		report(pid1, result(task, 300, &no))
	}
	recovered := poolTask(pid1, cleanupIDs[1])
	report(pid1, result(recovered, 301, &yes))
	report(pid1, result(recovered, 302, &yes))
	exec(`UPDATE v2_dispatch_check_target SET enabled=FALSE WHERE id=$1`, cleanupIDs[2])
	exec(`UPDATE v2_dispatch_check_binding SET reported_at=$2 WHERE target_id=$1`, cleanupIDs[3], time.Now().Unix()-1000)
	deleted, err := s.DeleteFaultyDispatchPool(ctx, cleanupIDs)
	if err != nil || deleted.Deleted != 1 || deleted.Skipped != 4 {
		t.Fatal("fault cleanup removed healthy/disabled/stale/referenced resource", deleted, err)
	}
	// A reference committed while cleanup is waiting must be visible to the
	// final reference query, rather than a stale scan outside the transaction.
	concurrentID, err := s.SaveDispatchPool(ctx, []DispatchPoolSave{makePool("192.0.2.24", 443)})
	if err != nil {
		t.Fatal(err)
	}
	report(pid1, result(poolTask(pid1, concurrentID[0]), 400, &no))
	writer, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	if _, err = writer.ExecContext(ctx, `INSERT INTO v2_server_vmess(id,host) VALUES(99,'192.0.2.24')`); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		value DispatchPoolDeleteResult
		err   error
	}
	done := make(chan outcome, 1)
	go func() { v, e := s.DeleteFaultyDispatchPool(ctx, concurrentID); done <- outcome{v, e} }()
	select {
	case v := <-done:
		t.Fatal("cleanup ignored concurrent config writer", v)
	case <-time.After(100 * time.Millisecond):
	}
	if err = writer.Commit(); err != nil {
		t.Fatal(err)
	}
	out := <-done
	if out.err != nil || out.value.Deleted != 0 || out.value.Skipped != 1 {
		t.Fatal("new reference not preserved", out)
	}
	// Budget overflow rolls the entire save back; disabling remains possible.
	exec(`INSERT INTO v2_dispatch_check_target(kind,host,port,name,enabled,check_interval_sec,tcp_timeout_ms,created_at) SELECT 'pool','198.51.100.'||n,443,'capacity',TRUE,30,1000,1 FROM generate_series(1,1000) n`)
	if _, err = s.SaveDispatchPool(ctx, []DispatchPoolSave{makePool("203.0.113.10", 443)}); !errors.Is(err, ErrDNSProbeInvalidRequest) {
		t.Fatal("capacity exceeded", err)
	}
	var inserted int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM v2_dispatch_check_target WHERE host='203.0.113.10'`).Scan(&inserted); err != nil || inserted != 0 {
		t.Fatal("overflow partially committed", inserted, err)
	}
}
