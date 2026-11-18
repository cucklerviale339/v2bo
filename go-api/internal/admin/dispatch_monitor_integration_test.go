package admin

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	"forest/go-api/internal/config"
	"forest/go-api/internal/platform/postgres"
)

func TestPostgresDispatchMonitorLifecycle(t *testing.T) {
	dsn := os.Getenv("DNS_FAILOVER_TEST_DSN")
	if dsn == "" {
		t.Skip("DNS_FAILOVER_TEST_DSN not set")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("test DSN must be a postgres URL")
	}
	root, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	schema := fmt.Sprintf("dispatch_test_%d", time.Now().UnixNano())
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	exec := func(statement string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, statement, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, kind := range []string{"shadowsocks", "vmess", "trojan", "tuic", "hysteria", "vless", "anytls", "v2node"} {
		exec("CREATE TABLE v2_server_" + kind + ` (id BIGINT PRIMARY KEY,host TEXT,"show" SMALLINT NOT NULL DEFAULT 1)`)
	}
	// Monitoring requires current recipients, without eligibility/permission
	// columns. Configured ownership still preserves unallocated numeric IDs.
	exec(`CREATE TABLE v2_user(id BIGINT PRIMARY KEY)`)
	exec(`INSERT INTO v2_user(id) VALUES(5),(15),(42)`)
	exec(`INSERT INTO v2_server_vmess(id,host,"show") VALUES(7,'base.example',1),(8,'disabled-bound.example',0),(9,'disabled-base.example',0)`)
	if err := postgres.EnsureNodeAddressSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO v2_node_address_group(id,name,created_at,updated_at) VALUES(1,'group',1,1);
INSERT INTO v2_node_address_binding(address_group_id,server_type,server_id,created_at,updated_at) VALUES(1,'vmess',7,1,1);
INSERT INTO v2_node_address_rule(group_id,host,match_user_id_ranges,created_at,updated_at) VALUES(1,'range.example','["10-100"]',1,1);
INSERT INTO v2_insider_rule(host,match_user_ids,created_at,updated_at) VALUES('inside.example','["42"]',1,1)`)
	exec(`INSERT INTO v2_node_address_group(id,name,created_at,updated_at) VALUES(2,'disabled node group',1,1);
INSERT INTO v2_node_address_binding(address_group_id,server_type,server_id,created_at,updated_at) VALUES(2,'vmess',8,1,1);
INSERT INTO v2_node_address_rule(group_id,host,match_user_id_ranges,created_at,updated_at) VALUES(2,'disabled-rule.example','["1-100"]',1,1)`)
	s := NewDBService(config.Config{}, db)
	entries, err := s.ListDispatchMonitors(ctx)
	if err != nil || len(entries) != 3 {
		t.Fatalf("catalog=%#v %v", entries, err)
	}
	for _, e := range entries {
		if e.Host == "range.example" && !reflect.DeepEqual(e.UserIDRanges, []string{"10-41", "43-100"}) {
			t.Fatal(e)
		}
	}
	// Repeat initialization through a new instance to exercise idempotent DDL.
	if err := NewDBService(config.Config{}, db).ensureDispatchMonitorSchema(ctx); err != nil {
		t.Fatal(err)
	}
	probe, err := s.CreateDNSProbe(ctx, DNSProbeCreateRequest{Name: "monitor"})
	if err != nil {
		t.Fatal(err)
	}
	pid := probe.Probe.ID
	req := DispatchMonitorSaveRequest{Host: "inside.example", CheckPort: 18443, Enabled: true, CheckIntervalSec: 10, TCPTimeoutMS: 500, ProbeIDs: []int64{pid}}
	if err := s.SaveDispatchMonitor(ctx, req); err != nil {
		t.Fatal(err)
	}
	heartbeat := func() {
		t.Helper()
		if _, err := s.HeartbeatDNSProbe(ctx, pid, DNSProbeHeartbeatRequest{Version: "test-monitor", Arch: "amd64", PublicIP: "192.0.2.7"}); err != nil {
			t.Fatal(err)
		}
	}
	heartbeat()
	getTask := func() DNSProbeTask {
		t.Helper()
		tasks, err := s.ListDispatchProbeTasks(ctx, pid)
		if err != nil || len(tasks) != 1 || tasks[0].TargetID >= 0 || tasks[0].RunID <= 0 {
			t.Fatalf("tasks=%#v %v", tasks, err)
		}
		return tasks[0]
	}
	task := getTask()
	if task.CheckPort != 18443 {
		t.Fatal(task)
	}
	success, latency := true, int64(12)
	makeResult := func(task DNSProbeTask, seq int64) DNSProbeResult {
		return DNSProbeResult{ResultID: fmt.Sprintf("%d-%d", task.TargetID, seq), TargetID: task.TargetID, TargetVersion: task.TargetVersion, RunID: task.RunID, Success: &success, LatencyMS: &latency, ResolvedIP: "192.0.2.1"}
	}
	report := func(r DNSProbeResult) DNSProbeReportResult {
		t.Helper()
		result, err := s.ReportDispatchProbeResults(ctx, pid, DNSProbeResultsRequest{Results: []DNSProbeResult{r}})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	old := makeResult(task, 100)
	if r := report(old); r.Accepted != 1 {
		t.Fatal(r)
	}
	if r := report(old); r.Duplicates != 1 {
		t.Fatal(r)
	}
	if r := report(makeResult(task, 99)); r.Duplicates != 1 {
		t.Fatal(r)
	}
	monitor := func() DispatchMonitor {
		t.Helper()
		entries, err := s.ListDispatchMonitors(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.Host == req.Host {
				return e
			}
		}
		t.Fatal("monitor missing")
		return DispatchMonitor{}
	}
	if m := monitor(); len(m.States) != 1 || m.States[0].Success == nil || !*m.States[0].Success {
		t.Fatalf("%#v", m)
	}
	req.CheckPort = 24443
	if err := s.SaveDispatchMonitor(ctx, req); err != nil {
		t.Fatal(err)
	}
	if m := monitor(); m.CheckPort != 24443 || m.States[0].Success != nil {
		t.Fatalf("stale port state: %#v", m)
	}
	if r := report(old); r.Skipped != 1 {
		t.Fatalf("old version revived: %#v", r)
	}
	task = getTask()
	if task.TargetVersion == old.TargetVersion {
		t.Fatal("configuration version unchanged")
	}
	current := makeResult(task, 101)
	if r := report(current); r.Accepted != 1 {
		t.Fatal(r)
	}
	// A disabled node must not contribute base addresses or rule-derived hosts.
	// Keeping its monitor configuration must not keep it visible or scheduled.
	exec(`UPDATE v2_server_vmess SET "show"=0 WHERE id=7`)
	if entries, err := s.ListDispatchMonitors(ctx); err != nil || len(entries) != 0 {
		t.Fatalf("disabled nodes still contribute entries: %#v %v", entries, err)
	}
	s.dispatchCacheMu.Lock()
	s.dispatchCachedHosts = nil
	s.dispatchCacheMu.Unlock()
	if tasks, err := s.ListDispatchProbeTasks(ctx, pid); err != nil || len(tasks) != 0 {
		t.Fatalf("disabled node still scheduled: %#v %v", tasks, err)
	}
	exec(`UPDATE v2_server_vmess SET "show"=1 WHERE id=7`)
	s.dispatchCacheMu.Lock()
	s.dispatchCachedHosts = nil
	s.dispatchCacheMu.Unlock()
	if restored := getTask(); restored.CheckPort != 24443 || restored.TargetVersion != task.TargetVersion {
		t.Fatalf("re-enabled node lost monitor configuration: %#v", restored)
	}
	exec(`UPDATE v2_dns_probe SET last_heartbeat_at=$2 WHERE id=$1`, pid, time.Now().Unix()-100)
	heartbeat()
	if m := monitor(); m.States[0].Success != nil {
		t.Fatal("reconnect retained previous session state")
	}
	if r := report(current); r.Skipped != 1 {
		t.Fatal("queued previous-session report revived health")
	}
	task = getTask()
	if task.RunID == current.RunID {
		t.Fatal("probe run did not advance")
	}
	if r := report(makeResult(task, 102)); r.Accepted != 1 {
		t.Fatal(r)
	}
	if _, err := s.SetDNSProbeEnabled(ctx, pid, false); err != nil {
		t.Fatal(err)
	}
	if tasks, err := s.ListDispatchProbeTasks(ctx, pid); err != nil || len(tasks) != 0 {
		t.Fatalf("revoked tasks: %#v %v", tasks, err)
	}
	if _, err := s.SetDNSProbeEnabled(ctx, pid, true); err != nil {
		t.Fatal(err)
	}
	heartbeat()
	if m := monitor(); m.States[0].Success != nil {
		t.Fatal("re-enabled probe retained state")
	}
	task = getTask()
	if r := report(makeResult(task, 103)); r.Accepted != 1 {
		t.Fatal(r)
	}
	exec(`UPDATE v2_insider_rule SET host='new.example'`)
	s.dispatchCacheMu.Lock()
	s.dispatchCachedHosts = nil
	s.dispatchCacheMu.Unlock()
	if tasks, err := s.ListDispatchProbeTasks(ctx, pid); err != nil || len(tasks) != 0 {
		t.Fatalf("removed address still scheduled: %#v %v", tasks, err)
	}
	// Missing auxiliary table must not abort the legacy heartbeat transaction.
	exec(`ALTER TABLE v2_dispatch_monitor_state RENAME TO broken_monitor_state`)
	exec(`UPDATE v2_dns_probe SET last_heartbeat_at=$2 WHERE id=$1`, pid, time.Now().Unix()-100)
	heartbeat()
	if _, err := s.ListDispatchProbeTasks(ctx, pid); err == nil {
		t.Fatal("broken monitor accepted tasks")
	}
	exec(`ALTER TABLE broken_monitor_state RENAME TO v2_dispatch_monitor_state`)
	if _, err := s.ListDispatchProbeTasks(ctx, pid); err != nil {
		t.Fatal("deferred reset did not recover", err)
	}
	if _, err := s.DeleteDNSProbe(ctx, pid); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM v2_dispatch_monitor_probe)+(SELECT count(*) FROM v2_dispatch_monitor_state)+(SELECT count(*) FROM v2_dns_failover_eval_outbox)`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("cascade or DNS isolation: %d %v", count, err)
	}
}
