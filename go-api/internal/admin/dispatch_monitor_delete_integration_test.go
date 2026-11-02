package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"forest/go-api/internal/config"
	"forest/go-api/internal/platform/postgres"
	usersvc "forest/go-api/internal/user"
)

type dispatchDeleteIntegration struct {
	t       *testing.T
	ctx     context.Context
	db      *sql.DB
	s       *DBService
	catalog *testDispatchCatalog
}

func newDispatchDeleteIntegration(t *testing.T) *dispatchDeleteIntegration {
	t.Helper()
	dsn := os.Getenv("DNS_FAILOVER_TEST_DSN")
	if dsn == "" {
		t.Skip("DNS_FAILOVER_TEST_DSN not set")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("test DSN must be a postgres URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	root, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	schema := fmt.Sprintf("dispatch_delete_%d", time.Now().UnixNano())
	if _, err := root.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if _, err := root.ExecContext(cleanupCtx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop isolated test schema: %v", err)
		}
	})
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	db, err := sql.Open("pgx", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	f := &dispatchDeleteIntegration{t: t, ctx: ctx, db: db}
	// Installer DROP statements are confined to this new, empty schema.
	installer, err := os.ReadFile("../../../database/install.pgsql.sql")
	if err != nil {
		t.Fatal(err)
	}
	f.exec(string(installer))
	if err := postgres.EnsureNodeAddressSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	f.exec(`INSERT INTO v2_server_group(id,name,created_at,updated_at) VALUES(1,'delete regression',1,1);
INSERT INTO v2_plan(id,group_id,transfer_enable,name,created_at,updated_at) VALUES(1,1,1000000,'delete plan',1,1);
INSERT INTO v2_user(id,email,password,uuid,token,group_id,plan_id,transfer_enable,created_at,updated_at)
SELECT id,'delete-'||id||'@example.test','password-hash','00000000-0000-0000-0000-'||lpad(id::text,12,'0'),lpad(id::text,32,'0'),1,1,1000000,1,1 FROM unnest(ARRAY[5,15,42,150]) id;
INSERT INTO v2_server_vmess(id,group_id,name,host,port,server_port,rate,network,"show",created_at,updated_at)
VALUES(7,'[1]','original node','base.example','443',443,'1','tcp',1,1,1);
INSERT INTO v2_node_address_group(id,name,created_at,updated_at) VALUES(1,'original addresses',1,1);
INSERT INTO v2_node_address_binding(address_group_id,server_type,server_id,created_at,updated_at) VALUES(1,'vmess',7,1,1);
INSERT INTO v2_node_address_rule(group_id,host,match_user_id_ranges,created_at,updated_at) VALUES(1,'range.example','["10-100"]',1,1);
INSERT INTO v2_insider_rule(host,match_user_ids,created_at,updated_at) VALUES('inside.example','["42"]',1,1)`)
	f.catalog = &testDispatchCatalog{entries: []usersvc.DispatchEntry{
		{Host: "base.example", UserIDs: []string{}, UserIDRanges: []string{"1-9", "101-9223372036854775807"}, Sources: []string{"node vmess #7"}},
		{Host: "inside.example", UserIDs: []string{"42"}, UserIDRanges: []string{}, Sources: []string{"insider #1"}},
		{Host: "range.example", UserIDs: []string{}, UserIDRanges: []string{"10-41", "43-100"}, Sources: []string{"address group #1"}},
	}}
	f.s = f.newService()
	return f
}

func (f *dispatchDeleteIntegration) newService() *DBService {
	s := NewDBService(config.Config{}, f.db)
	s.dispatchCatalog = f.catalog
	return s
}

func (f *dispatchDeleteIntegration) exec(statement string, args ...any) {
	f.t.Helper()
	if _, err := f.db.ExecContext(f.ctx, statement, args...); err != nil {
		f.t.Fatal(err)
	}
}

func (f *dispatchDeleteIntegration) snapshot(tables ...string) map[string]string {
	f.t.Helper()
	out := make(map[string]string, len(tables))
	for _, table := range tables {
		var data string
		if err := f.db.QueryRowContext(f.ctx, `SELECT COALESCE(jsonb_agg(v ORDER BY v::text),'[]'::jsonb)::text FROM (SELECT to_jsonb(t) v FROM "`+table+`" t) x`).Scan(&data); err != nil {
			f.t.Fatal(err)
		}
		out[table] = data
	}
	return out
}

func (f *dispatchDeleteIntegration) monitors(includeDeleted bool) map[string]DispatchMonitor {
	f.t.Helper()
	var entries []DispatchMonitor
	var err error
	if includeDeleted {
		entries, err = f.s.ListDispatchMonitorsIncludingDeleted(f.ctx)
	} else {
		entries, err = f.s.ListDispatchMonitors(f.ctx)
	}
	if err != nil {
		f.t.Fatal(err)
	}
	out := make(map[string]DispatchMonitor, len(entries))
	for _, entry := range entries {
		if _, duplicate := out[entry.Host]; duplicate {
			f.t.Fatalf("duplicate monitor: %s", entry.Host)
		}
		out[entry.Host] = entry
	}
	return out
}

func (f *dispatchDeleteIntegration) probe(name string) int64 {
	f.t.Helper()
	probe, err := f.s.CreateDNSProbe(f.ctx, DNSProbeCreateRequest{Name: name})
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.s.HeartbeatDNSProbe(f.ctx, probe.Probe.ID, DNSProbeHeartbeatRequest{Version: "delete-integration", Arch: "amd64", PublicIP: "192.0.2.7"}); err != nil {
		f.t.Fatal(err)
	}
	return probe.Probe.ID
}

func (f *dispatchDeleteIntegration) save(host string, probeIDs ...int64) {
	f.t.Helper()
	if err := f.s.SaveDispatchMonitor(f.ctx, DispatchMonitorSaveRequest{Host: host, CheckPort: 18443, Enabled: true, CheckIntervalSec: 30, TCPTimeoutMS: 500, ProbeIDs: probeIDs}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *dispatchDeleteIntegration) tasks(probeID int64) map[string]DNSProbeTask {
	f.t.Helper()
	tasks, err := f.s.ListDispatchProbeTasks(f.ctx, probeID)
	if err != nil {
		f.t.Fatal(err)
	}
	out := make(map[string]DNSProbeTask, len(tasks))
	for _, task := range tasks {
		out[task.CheckHost] = task
	}
	return out
}

func (f *dispatchDeleteIntegration) report(probeID int64, task DNSProbeTask, sequence int64, accepted, skipped int) {
	f.t.Helper()
	success, latency := true, int64(12)
	result, err := f.s.ReportDispatchProbeResults(f.ctx, probeID, DNSProbeResultsRequest{Results: []DNSProbeResult{{
		ResultID: fmt.Sprintf("%d-%d", task.TargetID, sequence), TargetID: task.TargetID,
		TargetVersion: task.TargetVersion, RunID: task.RunID, Success: &success, LatencyMS: &latency, ResolvedIP: "192.0.2.42",
	}}})
	if err != nil || result.Accepted != accepted || result.Skipped != skipped || result.Duplicates != 0 || len(result.GroupIDs) != 0 {
		f.t.Fatalf("report: %#v, err=%v; want accepted=%d skipped=%d", result, err, accepted, skipped)
	}
}

func (f *dispatchDeleteIntegration) persisted(host string) (id, version int64, enabled, deleted bool, bindings, states int) {
	f.t.Helper()
	err := f.db.QueryRowContext(f.ctx, `SELECT m.id,m.version,m.enabled,m.deleted,
(SELECT count(*) FROM v2_dispatch_monitor_probe b WHERE b.monitor_id=m.id),
(SELECT count(*) FROM v2_dispatch_monitor_state s WHERE s.monitor_id=m.id)
FROM v2_dispatch_monitor m WHERE m.host=$1`, host).Scan(&id, &version, &enabled, &deleted, &bindings, &states)
	if err != nil {
		f.t.Fatal(err)
	}
	return
}

func TestPostgresDispatchMonitorDeleteRestoreLifecycle(t *testing.T) {
	f := newDispatchDeleteIntegration(t)
	initial := f.monitors(false)
	if len(initial) != 3 || initial["base.example"].ID != 0 || initial["base.example"].Deleted {
		t.Fatalf("unconfigured catalog candidates: %#v", initial)
	}
	pid, secondPID := f.probe("primary"), f.probe("secondary")
	f.save("inside.example", pid, secondPID)
	f.save("range.example", pid)
	oldTask := f.tasks(pid)["inside.example"]
	secondTask := f.tasks(secondPID)["inside.example"]
	f.report(pid, oldTask, 100, 1, 0)
	f.report(secondPID, secondTask, 100, 1, 0)
	f.report(pid, f.tasks(pid)["range.example"], 100, 1, 0)
	before := f.monitors(false)
	if states := before["inside.example"].States; len(states) != 2 || states[0].Success == nil || !*states[0].Success || states[1].Success == nil {
		t.Fatalf("configured monitor did not acquire health: %#v", states)
	}
	oldID, oldVersion, _, _, _, _ := f.persisted("inside.example")
	legacyTables := []string{"v2_user", "v2_plan", "v2_server_group", "v2_server_vmess", "v2_node_address_group", "v2_node_address_binding", "v2_node_address_rule", "v2_insider_rule", "v2_dns_probe", "v2_dns_failover_group", "v2_dns_failover_target", "v2_dns_failover_eval_outbox"}
	legacyBefore := f.snapshot(legacyTables...)
	subscriptions := func() map[int64][]map[string]any {
		t.Helper()
		out := map[int64][]map[string]any{}
		for id, host := range map[int64]string{5: "base.example", 15: "range.example", 42: "inside.example", 150: "base.example"} {
			nodes, err := usersvc.NewDBService(config.Config{}, f.db).Servers(f.ctx, id, "delete-client")
			if err != nil || len(nodes) != 1 || fmt.Sprint(nodes[0]["host"]) != host {
				t.Fatalf("subscription %d: %#v, err=%v, want host=%s", id, nodes, err, host)
			}
			out[id] = nodes
		}
		return out
	}
	beforeSubscriptions := subscriptions()
	assertOriginalData := func() {
		t.Helper()
		if after := f.snapshot(legacyTables...); !reflect.DeepEqual(legacyBefore, after) {
			t.Fatalf("monitor deletion/restoration changed original tables: before=%v after=%v", legacyBefore, after)
		}
		if after := subscriptions(); !reflect.DeepEqual(beforeSubscriptions, after) {
			t.Fatalf("monitor deletion/restoration changed subscription nodes: %#v", after)
		}
	}
	deleteHosts := []string{" INSIDE.EXAMPLE. ", "BASE.EXAMPLE.", "inside.example"}
	if err := f.s.DeleteDispatchMonitors(f.ctx, deleteHosts); err != nil {
		t.Fatal(err)
	}
	assertDeleted := func() {
		t.Helper()
		visible := f.monitors(false)
		if len(visible) != 1 || visible["range.example"].ID != before["range.example"].ID {
			t.Fatalf("deleted entries leaked into default list: %#v", visible)
		}
		all := f.monitors(true)
		if len(all) != 3 {
			t.Fatalf("including-deleted inventory lost catalog entries: %#v", all)
		}
		for _, host := range []string{"base.example", "inside.example"} {
			m := all[host]
			if m.ID <= 0 || !m.Deleted || m.Enabled || len(m.ProbeIDs) != 0 || len(m.States) != 0 || !reflect.DeepEqual(m.DispatchEntry, initial[host].DispatchEntry) {
				t.Fatalf("invalid tombstone for %s: %#v", host, m)
			}
			_, _, enabled, deleted, bindings, states := f.persisted(host)
			if enabled || !deleted || bindings != 0 || states != 0 {
				t.Fatalf("delete did not clear %s: enabled=%v deleted=%v bindings=%d states=%d", host, enabled, deleted, bindings, states)
			}
		}
		if tasks := f.tasks(pid); len(tasks) != 1 || tasks["range.example"].TargetID == 0 {
			t.Fatalf("deleted monitor still scheduled: %#v", tasks)
		}
		if tasks := f.tasks(secondPID); len(tasks) != 0 {
			t.Fatalf("deleted secondary binding still scheduled: %#v", tasks)
		}
	}
	assertDeleted()
	id, deletedVersion, _, _, _, _ := f.persisted("inside.example")
	if id != oldID || deletedVersion != oldVersion+1 {
		t.Fatalf("delete identity/version: id=%d version=%d, before id=%d version=%d", id, deletedVersion, oldID, oldVersion)
	}
	baseID, baseVersion, _, _, _, _ := f.persisted("base.example")
	if baseVersion != 1 {
		t.Fatalf("unconfigured candidate tombstone version=%d", baseVersion)
	}
	if unrelated := f.monitors(false)["range.example"]; !reflect.DeepEqual(before["range.example"], unrelated) {
		t.Fatalf("delete changed unrelated monitor: before=%#v after=%#v", before["range.example"], unrelated)
	}
	f.report(pid, oldTask, 101, 0, 1)
	f.report(secondPID, secondTask, 101, 0, 1)
	assertDeleted()
	assertOriginalData()
	if err := f.s.DeleteDispatchMonitors(f.ctx, deleteHosts); err != nil {
		t.Fatalf("repeat delete: %v", err)
	}
	assertDeleted()
	if id, version, _, _, _, _ := f.persisted("inside.example"); id != oldID || version != deletedVersion+1 {
		t.Fatalf("repeat delete identity/version: id=%d version=%d", id, version)
	}
	if id, version, _, _, _, _ := f.persisted("base.example"); id != baseID || version != baseVersion+1 {
		t.Fatalf("repeat unconfigured delete created another tombstone: id=%d version=%d", id, version)
	}
	tombstones := f.snapshot("v2_dispatch_monitor")
	// A new service reruns the migration and resets sessions, retaining deletion.
	f.s = f.newService()
	if err := f.s.InitializeDispatchMonitorSchema(f.ctx); err != nil {
		t.Fatal(err)
	}
	assertDeleted()
	if after := f.snapshot("v2_dispatch_monitor"); !reflect.DeepEqual(tombstones, after) {
		t.Fatalf("restart changed durable deletion configuration: before=%v after=%v", tombstones, after)
	}
	f.report(pid, oldTask, 102, 0, 1)
	assertOriginalData()
	_, restoreFromVersion, _, _, _, _ := f.persisted("inside.example")
	f.save("inside.example", pid, secondPID)
	id, version, enabled, deleted, bindings, states := f.persisted("inside.example")
	if id != oldID || version != restoreFromVersion+1 || !enabled || deleted || bindings != 2 || states != 0 {
		t.Fatalf("restore persisted stale configuration/state: id=%d version=%d enabled=%v deleted=%v bindings=%d states=%d", id, version, enabled, deleted, bindings, states)
	}
	assertRestoredEmpty := func() {
		t.Helper()
		m := f.monitors(false)["inside.example"]
		if len(f.monitors(false)) != 2 || m.Deleted || !m.Enabled || len(m.States) != 2 || !reflect.DeepEqual(m.ProbeIDs, []int64{pid, secondPID}) {
			t.Fatalf("restored monitor missing or rebound incorrectly: %#v", m)
		}
		for _, state := range m.States {
			if state.Success != nil || state.LatencyMS != nil || state.ReportedAt != nil || state.Error != "" || state.ResolvedIP != "" || !state.Stale {
				t.Fatalf("restored health was not cleared: %#v", state)
			}
		}
	}
	assertRestoredEmpty()
	newTask := f.tasks(pid)["inside.example"]
	if newTask.TargetID != oldTask.TargetID || newTask.TargetVersion != version || newTask.CheckPort != 18443 {
		t.Fatalf("restored task: %#v", newTask)
	}
	// Match the restored session so this rejection specifically proves version fencing.
	staleVersionTask := newTask
	staleVersionTask.TargetVersion = oldTask.TargetVersion
	f.report(pid, staleVersionTask, 1000, 0, 1)
	f.report(secondPID, secondTask, 1000, 0, 1)
	assertRestoredEmpty()
	f.report(pid, newTask, 1, 1, 0)
	if m := f.monitors(false)["inside.example"]; m.States[0].Success == nil || !*m.States[0].Success {
		t.Fatalf("fresh restored task did not accept health: %#v", m)
	}
	// An initially unconfigured candidate can also be restored through Save.
	f.save("base.example", pid)
	if id, version, enabled, deleted, bindings, states := f.persisted("base.example"); id != baseID || version != baseVersion+2 || !enabled || deleted || bindings != 1 || states != 0 {
		t.Fatalf("candidate restore: id=%d version=%d enabled=%v deleted=%v bindings=%d states=%d", id, version, enabled, deleted, bindings, states)
	}
	if len(f.monitors(false)) != 3 || len(f.tasks(pid)) != 3 {
		t.Fatal("restored candidate did not return to inventory and scheduling")
	}
	assertOriginalData()
}

func TestPostgresDispatchMonitorDeleteBatchAtomicity(t *testing.T) {
	f := newDispatchDeleteIntegration(t)
	f.monitors(false)
	pid := f.probe("atomic-delete")
	f.save("inside.example", pid)
	task := f.tasks(pid)["inside.example"]
	f.report(pid, task, 100, 1, 0)
	tables := []string{"v2_dispatch_monitor", "v2_dispatch_monitor_probe", "v2_dispatch_monitor_state"}
	before := f.snapshot(tables...)
	beforeMonitors := f.monitors(true)
	beforeTasks := f.tasks(pid)
	assertUnchanged := func() {
		t.Helper()
		if after := f.snapshot(tables...); !reflect.DeepEqual(before, after) {
			t.Fatalf("failed batch partially changed monitor rows/bindings/health: before=%v after=%v", before, after)
		}
		if after := f.monitors(true); !reflect.DeepEqual(beforeMonitors, after) {
			t.Fatalf("failed batch changed visible monitor configuration: %#v", after)
		}
		if after := f.tasks(pid); !reflect.DeepEqual(beforeTasks, after) {
			t.Fatalf("failed batch changed scheduling: %#v", after)
		}
	}
	tooMany := make([]string, 501)
	for i := range tooMany {
		tooMany[i] = "inside.example"
	}
	cases := []struct {
		name  string
		hosts []string
	}{
		{"nil", nil},
		{"empty", []string{}},
		{"too many", tooMany},
		{"empty host after valid hosts", []string{"base.example", "inside.example", " "}},
		{"invalid syntax after valid hosts", []string{"base.example", "inside.example", "https://invalid.example/path"}},
		{"unknown catalog host after valid hosts", []string{"base.example", "inside.example", "unknown.example"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := f.s.DeleteDispatchMonitors(f.ctx, tc.hosts); !errors.Is(err, ErrDNSProbeInvalidRequest) {
				t.Fatalf("invalid batch error=%v, want ErrDNSProbeInvalidRequest", err)
			}
			assertUnchanged()
		})
	}
	// 'range' sorts after the unconfigured 'base' insert and configured 'inside'
	// update/cascade. Its real SQL failure must undo both earlier operations.
	f.exec(`ALTER TABLE v2_dispatch_monitor ADD CONSTRAINT dispatch_delete_test_reject_range CHECK (host <> 'range.example' OR deleted=FALSE)`)
	if err := f.s.DeleteDispatchMonitors(f.ctx, []string{"inside.example", "range.example", "base.example"}); err == nil || !strings.Contains(err.Error(), "dispatch_delete_test_reject_range") {
		t.Fatalf("expected the last host's PostgreSQL constraint failure, got %v", err)
	}
	assertUnchanged()
	f.exec(`ALTER TABLE v2_dispatch_monitor DROP CONSTRAINT dispatch_delete_test_reject_range`)
	// The same batch succeeds after removing only the injected failure.
	if err := f.s.DeleteDispatchMonitors(f.ctx, []string{"inside.example", "range.example", "base.example"}); err != nil {
		t.Fatal(err)
	}
	if len(f.monitors(false)) != 0 || len(f.monitors(true)) != 3 || len(f.tasks(pid)) != 0 {
		t.Fatal("valid multi-host delete did not commit all tombstones")
	}
	for _, entry := range f.catalog.entries {
		_, _, enabled, deleted, bindings, states := f.persisted(entry.Host)
		if enabled || !deleted || bindings != 0 || states != 0 {
			t.Fatalf("valid batch only partially deleted %s", entry.Host)
		}
	}
}

func TestPostgresDispatchMonitorDeleteSchemaUpgrade(t *testing.T) {
	f := newDispatchDeleteIntegration(t)
	// Simulate the populated monitoring table from before soft deletion existed.
	f.exec(`CREATE TABLE v2_dispatch_monitor (
id BIGSERIAL PRIMARY KEY, host VARCHAR(253) NOT NULL UNIQUE,
check_port INTEGER NOT NULL CHECK (check_port BETWEEN 1 AND 65535), enabled BOOLEAN NOT NULL DEFAULT FALSE,
check_interval_sec INTEGER NOT NULL CHECK(check_interval_sec BETWEEN 1 AND 86400),
tcp_timeout_ms INTEGER NOT NULL CHECK(tcp_timeout_ms BETWEEN 1 AND 60000), version BIGINT NOT NULL DEFAULT 1);
INSERT INTO v2_dispatch_monitor(host,check_port,enabled,check_interval_sec,tcp_timeout_ms,version)
VALUES('inside.example',24443,TRUE,10,700,7)`)
	if err := f.s.InitializeDispatchMonitorSchema(f.ctx); err != nil {
		t.Fatal(err)
	}
	upgraded := f.monitors(false)
	m := upgraded["inside.example"]
	if len(upgraded) != 3 || m.ID <= 0 || m.Deleted || !m.Enabled || m.CheckPort != 24443 || m.CheckIntervalSec != 10 || m.TCPTimeoutMS != 700 {
		t.Fatalf("migration lost legacy monitor configuration/default candidates: %#v", upgraded)
	}
	id, version, _, deleted, _, _ := f.persisted("inside.example")
	if version != 7 || deleted {
		t.Fatalf("migration changed legacy version/deletion: version=%d deleted=%v", version, deleted)
	}
	if err := f.s.DeleteDispatchMonitors(f.ctx, []string{"inside.example", "base.example"}); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot("v2_dispatch_monitor")
	for i := 0; i < 2; i++ {
		f.s = f.newService()
		if err := f.s.InitializeDispatchMonitorSchema(f.ctx); err != nil {
			t.Fatal(err)
		}
		visible, all := f.monitors(false), f.monitors(true)
		if len(visible) != 1 || visible["range.example"].Host != "range.example" || len(all) != 3 || !all["inside.example"].Deleted || !all["base.example"].Deleted {
			t.Fatalf("restart %d resurrected deleted entries: visible=%#v all=%#v", i, visible, all)
		}
		if after := f.snapshot("v2_dispatch_monitor"); !reflect.DeepEqual(before, after) {
			t.Fatalf("restart %d changed tombstones: before=%v after=%v", i, before, after)
		}
	}
	if restoredID, version, enabled, deleted, _, _ := f.persisted("inside.example"); restoredID != id || version != 8 || enabled || !deleted {
		t.Fatalf("upgraded deletion identity/version: id=%d version=%d enabled=%v deleted=%v", restoredID, version, enabled, deleted)
	}
}

func TestPostgresDispatchMonitorDeleteConcurrentReverseReports(t *testing.T) {
	f := newDispatchDeleteIntegration(t)
	f.monitors(false)
	var schema string
	if err := f.db.QueryRowContext(f.ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	worker := func() (*DBService, int) {
		t.Helper()
		parsed, err := url.Parse(os.Getenv("DNS_FAILOVER_TEST_DSN"))
		if err != nil {
			t.Fatal(err)
		}
		query := parsed.Query()
		query.Set("search_path", schema)
		query.Set("lock_timeout", "1500ms")
		query.Set("statement_timeout", "3s")
		parsed.RawQuery = query.Encode()
		db, err := sql.Open("pgx", parsed.String())
		if err != nil {
			t.Fatal(err)
		}
		// Keep a known backend PID for observing each concurrent operation.
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		t.Cleanup(func() { db.Close() })
		s := NewDBService(config.Config{}, db)
		s.dispatchCatalog = f.catalog
		if err := s.InitializeDispatchMonitorSchema(f.ctx); err != nil {
			t.Fatal(err)
		}
		var pid int
		if err := db.QueryRowContext(f.ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			t.Fatal(err)
		}
		return s, pid
	}
	deleter, deletePID := worker()
	reporter, reportPID := worker()
	probeID := f.probe("concurrent-delete")
	// Assign IDs opposite to lexical host order, which the delete input also uses.
	hostsByID := []string{"range.example", "inside.example", "base.example"}
	hostsByName := []string{"base.example", "inside.example", "range.example"}
	for _, host := range hostsByID {
		f.save(host, probeID)
	}
	initialTasks := f.tasks(probeID)
	if !(initialTasks["range.example"].TargetID > initialTasks["inside.example"].TargetID && initialTasks["inside.example"].TargetID > initialTasks["base.example"].TargetID && initialTasks["base.example"].TargetID < 0) {
		t.Fatalf("fixture must have host order opposite to positive monitor IDs: %#v", initialTasks)
	}
	highestID := -initialTasks["base.example"].TargetID
	type outcome struct {
		operation string
		summary   DNSProbeReportResult
		err       error
	}
	contend := func(deleteFirst bool, request DNSProbeResultsRequest) error {
		ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
		defer cancel()
		gate, err := f.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		var wg sync.WaitGroup
		defer func() {
			cancel()
			gate.Rollback()
			wg.Wait()
		}()
		var id int64
		if err := gate.QueryRowContext(ctx, `SELECT id FROM v2_dispatch_monitor WHERE id=$1 FOR UPDATE`, highestID).Scan(&id); err != nil {
			return err
		}
		done := make(chan outcome, 2)
		start := func(deleting bool) int {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if deleting {
					done <- outcome{operation: "delete", err: deleter.DeleteDispatchMonitors(ctx, hostsByName)}
				} else {
					summary, err := reporter.ReportDispatchProbeResults(ctx, probeID, request)
					done <- outcome{operation: "report", summary: summary, err: err}
				}
			}()
			if deleting {
				return deletePID
			}
			return reportPID
		}
		waitBlocked := func(pid int) error {
			deadline := time.NewTimer(time.Second)
			defer deadline.Stop()
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for {
				var blocked bool
				if err := f.db.QueryRowContext(ctx, `SELECT cardinality(pg_blocking_pids($1))>0`, pid).Scan(&blocked); err != nil {
					return err
				}
				if blocked {
					return nil
				}
				select {
				case result := <-done:
					return fmt.Errorf("%s finished before the lock barrier: %v", result.operation, result.err)
				case <-deadline.C:
					return fmt.Errorf("backend %d did not reach the lock barrier within one second", pid)
				case <-ctx.Done():
					return ctx.Err()
				case <-ticker.C:
				}
			}
		}
		// With either fix removed, one of these launch orders lets one operation
		// hold a low ID while its peer holds a high ID after the gate is released.
		if err := waitBlocked(start(deleteFirst)); err != nil {
			return err
		}
		if err := waitBlocked(start(!deleteFirst)); err != nil {
			return err
		}
		if err := gate.Rollback(); err != nil {
			return err
		}
		for i := 0; i < 2; i++ {
			select {
			case result := <-done:
				if result.err != nil {
					return fmt.Errorf("%s failed under contention: %w", result.operation, result.err)
				}
				if result.operation == "report" {
					accepted, skipped := len(request.Results), 0
					if deleteFirst {
						accepted, skipped = 0, len(request.Results)
					}
					if result.summary.Accepted != accepted || result.summary.Skipped != skipped || result.summary.Duplicates != 0 || len(result.summary.GroupIDs) != 0 {
						return fmt.Errorf("report summary=%#v, want accepted=%d skipped=%d", result.summary, accepted, skipped)
					}
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	for round := 0; round < 20; round++ {
		for _, host := range hostsByID {
			f.save(host, probeID)
		}
		tasks := f.tasks(probeID)
		for _, host := range hostsByID {
			f.report(probeID, tasks[host], 100, 1, 0)
		}
		request := DNSProbeResultsRequest{Results: []DNSProbeResult{}}
		success, latency := true, int64(12)
		// Positive IDs descend on the wire. Interleave two observations per
		// target so stable sorting must preserve their ascending sequence order.
		for _, sequence := range []int64{200, 201} {
			for _, host := range hostsByName {
				task := tasks[host]
				request.Results = append(request.Results, DNSProbeResult{
					ResultID: fmt.Sprintf("%d-%d", task.TargetID, sequence), TargetID: task.TargetID,
					TargetVersion: task.TargetVersion, RunID: task.RunID,
					Success: &success, LatencyMS: &latency, ResolvedIP: "192.0.2.42",
				})
			}
		}
		original := append([]DNSProbeResult(nil), request.Results...)
		deleteFirst := round%2 == 0
		if err := contend(deleteFirst, request); err != nil {
			t.Fatalf("round %d (delete first=%v): %v", round, deleteFirst, err)
		}
		if !reflect.DeepEqual(original, request.Results) {
			t.Fatalf("round %d reordered the caller's results", round)
		}
		for _, host := range hostsByID {
			_, _, enabled, deleted, bindings, states := f.persisted(host)
			if enabled || !deleted || bindings != 0 || states != 0 {
				t.Fatalf("round %d left %s enabled=%v deleted=%v bindings=%d states=%d", round, host, enabled, deleted, bindings, states)
			}
		}
		if len(f.monitors(false)) != 0 || len(f.monitors(true)) != 3 || len(f.tasks(probeID)) != 0 {
			t.Fatalf("round %d left deleted monitors visible or scheduled", round)
		}
		// Replaying the queued batch after delete must not recreate any state.
		summary, err := reporter.ReportDispatchProbeResults(f.ctx, probeID, request)
		if err != nil || summary.Accepted != 0 || summary.Skipped != len(request.Results) || summary.Duplicates != 0 {
			t.Fatalf("round %d replay: summary=%#v err=%v", round, summary, err)
		}
		var states int
		if err := f.db.QueryRowContext(f.ctx, `SELECT count(*) FROM v2_dispatch_monitor_state`).Scan(&states); err != nil || states != 0 {
			t.Fatalf("round %d replay left state rows=%d err=%v", round, states, err)
		}
	}
}
