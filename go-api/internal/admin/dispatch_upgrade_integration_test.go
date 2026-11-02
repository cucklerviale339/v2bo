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
	usersvc "forest/go-api/internal/user"
)

// The installer, original DNS schema and subscription implementation are
// unchanged from b21c39c. Exercise the upgrade against populated legacy tables,
// rather than only testing initialization on an empty monitor database.
func TestPostgresDispatchUpgradePreservesBaselineData(t *testing.T) {
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
	schema := fmt.Sprintf("dispatch_upgrade_%d", time.Now().UnixNano())
	if _, err = root.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	defer root.Exec("DROP SCHEMA " + schema + " CASCADE")
	q := parsed.Query()
	q.Set("search_path", schema)
	parsed.RawQuery = q.Encode()
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
	installer, err := os.ReadFile("../../../database/install.pgsql.sql")
	if err != nil {
		t.Fatal(err)
	}
	// The install SQL contains DROP statements: it is run only in this unique,
	// empty test schema, never in the DSN's existing application schema.
	exec(string(installer))
	if err := postgres.EnsureNodeAddressSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := postgres.EnsureDNSFailoverSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO v2_server_group(id,name,created_at,updated_at) VALUES(1,'legacy',1,1);
INSERT INTO v2_plan(id,group_id,transfer_enable,name,created_at,updated_at) VALUES(1,1,1000000,'legacy plan',1,1);
INSERT INTO v2_user(id,email,password,uuid,token,group_id,plan_id,transfer_enable,created_at,updated_at)
SELECT id,'legacy-'||id||'@example.test','legacy-password-hash','00000000-0000-0000-0000-'||lpad(id::text,12,'0'),lpad(id::text,32,'0'),1,1,1000000,1,1 FROM unnest(ARRAY[5,15,42,150]) id;
INSERT INTO v2_server_vmess(id,group_id,name,host,port,server_port,rate,network,"show",created_at,updated_at)
VALUES(7,'[1]','legacy node','base.example','443',443,'1','tcp',1,1,1);
INSERT INTO v2_node_address_group(id,name,created_at,updated_at) VALUES(1,'legacy addresses',1,1);
INSERT INTO v2_node_address_binding(address_group_id,server_type,server_id,created_at,updated_at) VALUES(1,'vmess',7,1,1);
INSERT INTO v2_node_address_rule(group_id,host,match_user_id_ranges,created_at,updated_at) VALUES(1,'range.example','["10-100"]',1,1);
INSERT INTO v2_insider_rule(host,match_user_ids,created_at,updated_at) VALUES('inside.example','["42"]',1,1);
INSERT INTO v2_subscribe_access_log(user_id,client_ip,user_agent,accessed_at,created_at) VALUES(42,'192.0.2.42','legacy client',1,1);
INSERT INTO v2_runtime_kv(k,v,expire_at,created_at,updated_at) VALUES('legacy-config','preserve-me',0,1,1)`)
	legacy := NewDBService(config.Config{}, db)
	probe, err := legacy.CreateDNSProbe(ctx, DNSProbeCreateRequest{Name: "legacy-probe"})
	if err != nil {
		t.Fatal(err)
	}
	req := validDNSFailoverRuleSaveRequest()
	req.ProbeIDs = []int64{probe.Probe.ID}
	if _, err := legacy.SaveDNSFailoverRule(ctx, req); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.HeartbeatDNSProbe(ctx, probe.Probe.ID, DNSProbeHeartbeatRequest{Version: "b21c39c", Arch: "amd64", PublicIP: "192.0.2.7"}); err != nil {
		t.Fatal(err)
	}
	oldTasks, err := legacy.ListDNSProbeTasks(ctx, probe.Probe.ID)
	if err != nil || len(oldTasks) == 0 {
		t.Fatalf("legacy tasks: %v %v", oldTasks, err)
	}
	userService := usersvc.NewDBService(config.Config{}, db)
	subscriptions := map[int64][]map[string]any{}
	for id, expectedHost := range map[int64]string{5: "base.example", 15: "range.example", 42: "inside.example", 150: "base.example"} {
		nodes, err := userService.Servers(ctx, id, "legacy-client")
		if err != nil || len(nodes) != 1 || fmt.Sprint(nodes[0]["host"]) != expectedHost {
			t.Fatalf("legacy subscription %d: %v %v", id, nodes, err)
		}
		subscriptions[id] = nodes
	}
	var oldTables []string
	rows, err := db.QueryContext(ctx, `SELECT tablename FROM pg_tables WHERE schemaname=current_schema() ORDER BY tablename`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		oldTables = append(oldTables, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	snapshot := func() map[string]string {
		t.Helper()
		out := map[string]string{}
		for _, table := range oldTables {
			var data string
			if err := db.QueryRowContext(ctx, `SELECT COALESCE(jsonb_agg(v ORDER BY v::text),'[]'::jsonb)::text FROM (SELECT to_jsonb(t) v FROM "`+table+`" t) x`).Scan(&data); err != nil {
				t.Fatal(err)
			}
			out[table] = data
		}
		return out
	}
	before := snapshot()
	upgraded := NewDBService(config.Config{}, db)
	if err := upgraded.InitializeDispatchMonitorSchema(ctx); err != nil {
		t.Fatal(err)
	}
	var newTables int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pg_tables WHERE schemaname=current_schema() AND tablename LIKE 'v2_dispatch_%'`).Scan(&newTables); err != nil || newTables != 13 {
		t.Fatalf("auxiliary tables: %d %v", newTables, err)
	}
	if _, err := upgraded.ListDispatchMonitors(ctx); err != nil {
		t.Fatal(err)
	}
	if err := upgraded.SaveDispatchMonitor(ctx, DispatchMonitorSaveRequest{Host: "inside.example", CheckPort: 18443, Enabled: true, CheckIntervalSec: 30, TCPTimeoutMS: 3000, ProbeIDs: []int64{probe.Probe.ID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := upgraded.SaveDispatchPool(ctx, []DispatchPoolSave{{IP: "192.0.2.123", Port: 24443, Enabled: true, CheckIntervalSec: 30, TCPTimeoutMS: 3000}}); err != nil {
		t.Fatal(err)
	}
	if _, err := upgraded.ListDispatchCheckTasks(ctx, probe.Probe.ID); err != nil {
		t.Fatal(err)
	}
	// Reinitialization/restart is idempotent and only resets auxiliary state.
	if err := NewDBService(config.Config{}, db).InitializeDispatchMonitorSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if after := snapshot(); !reflect.DeepEqual(before, after) {
		for table := range before {
			if before[table] != after[table] {
				t.Errorf("upgrade changed legacy table %s", table)
			}
		}
	}
	if tasks, err := upgraded.ListDNSProbeTasks(ctx, probe.Probe.ID); err != nil || !reflect.DeepEqual(oldTasks, tasks) {
		t.Fatalf("legacy DNS tasks changed: %v %v", tasks, err)
	}
	if identity, err := upgraded.AuthenticateDNSProbe(ctx, probe.Secret); err != nil || identity.ID != probe.Probe.ID {
		t.Fatalf("legacy probe token invalidated: %v", err)
	}
	for id, beforeNodes := range subscriptions {
		nodes, err := usersvc.NewDBService(config.Config{}, db).Servers(ctx, id, "legacy-client")
		if err != nil || !reflect.DeepEqual(beforeNodes, nodes) {
			t.Fatalf("subscription %d changed after monitoring configuration: %v", id, err)
		}
	}
	// Compare inventory with real subscription selection while toggling both
	// address switches. Disabled groups/rules fall back to the managed host.
	if err := upgraded.SaveDispatchMonitor(ctx, DispatchMonitorSaveRequest{Host: "range.example", CheckPort: 24443, Enabled: true, CheckIntervalSec: 30, TCPTimeoutMS: 3000, ProbeIDs: []int64{probe.Probe.ID}}); err != nil {
		t.Fatal(err)
	}
	checkHosts := func(want []string, userID int64, wantHost string) {
		t.Helper()
		entries, err := upgraded.ListDispatchMonitors(ctx)
		if err != nil {
			t.Fatal(err)
		}
		hosts := make([]string, 0, len(entries))
		for _, e := range entries {
			hosts = append(hosts, e.Host)
		}
		if !reflect.DeepEqual(hosts, want) {
			t.Fatalf("inventory=%v want=%v", hosts, want)
		}
		nodes, err := usersvc.NewDBService(config.Config{}, db).Servers(ctx, userID, "legacy-client")
		if err != nil {
			t.Fatal(err)
		}
		if wantHost == "" {
			if len(nodes) != 0 {
				t.Fatalf("disabled node still dispatched: %v", nodes)
			}
		} else if len(nodes) != 1 || fmt.Sprint(nodes[0]["host"]) != wantHost {
			t.Fatalf("dispatched=%v want=%s", nodes, wantHost)
		}
		// Production polling refreshes the catalog cache within five seconds.
		upgraded.dispatchCacheMu.Lock()
		upgraded.dispatchCachedHosts = nil
		upgraded.dispatchCacheMu.Unlock()
		tasks, err := upgraded.ListDispatchProbeTasks(ctx, probe.Probe.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, task := range tasks {
			found := false
			for _, host := range want {
				found = found || task.CheckHost == host
			}
			if !found {
				t.Fatalf("non-dispatched address still scheduled: %#v", task)
			}
		}
	}
	for _, table := range []string{"v2_node_address_group", "v2_node_address_rule"} {
		exec("UPDATE " + table + " SET enabled=0")
		checkHosts([]string{"base.example", "inside.example"}, 15, "base.example")
		exec("UPDATE " + table + " SET enabled=1")
		checkHosts([]string{"base.example", "inside.example", "range.example"}, 15, "range.example")
	}
	// Unbound groups do not contribute addresses, even when enabled.
	exec(`INSERT INTO v2_node_address_group(id,name,created_at,updated_at) VALUES(2,'unbound',1,1);
INSERT INTO v2_node_address_rule(group_id,host,match_user_id_ranges,created_at,updated_at) VALUES(2,'unbound.example','["1-100"]',1,1)`)
	checkHosts([]string{"base.example", "inside.example", "range.example"}, 15, "range.example")
	// An enabled managed host fully overridden by higher priority rules is not
	// part of the dispatch chain and must disappear from inventory and tasks.
	if err := upgraded.SaveDispatchMonitor(ctx, DispatchMonitorSaveRequest{Host: "base.example", CheckPort: 34443, Enabled: true, CheckIntervalSec: 30, TCPTimeoutMS: 3000, ProbeIDs: []int64{probe.Probe.ID}}); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE v2_node_address_rule SET match_user_id_ranges='["1-9223372036854775807"]' WHERE group_id=1`)
	checkHosts([]string{"inside.example", "range.example"}, 5, "range.example")
	exec(`UPDATE v2_server_vmess SET "show"=0 WHERE id=7`)
	checkHosts([]string{}, 15, "")
}
