package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"forest/go-api/internal/platform/postgres"
)

func TestPostgresDNSUpgradeAndProbeLifecycle(t *testing.T) {
	dsn := os.Getenv("DNS_FAILOVER_TEST_DSN")
	if dsn == "" {
		t.Skip("DNS_FAILOVER_TEST_DSN not set")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("test DSN must be a postgres URL")
	}
	rootDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer rootDB.Close()
	schema := fmt.Sprintf("dns_upgrade_test_%d", time.Now().UnixNano())
	if _, err = rootDB.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	defer rootDB.Exec("DROP SCHEMA " + schema + " CASCADE")
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
	if _, err = db.ExecContext(ctx, `CREATE TABLE v2_user (id BIGINT PRIMARY KEY, token TEXT);
INSERT INTO v2_user VALUES (42, 'unchanged-subscription');
CREATE TABLE v2_subscribe_access_log (id BIGINT, user_id BIGINT);
INSERT INTO v2_subscribe_access_log VALUES (1, 42)`); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := postgres.EnsureDNSFailoverSchema(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	var token string
	var oldRows, dnsTables int
	if err := db.QueryRowContext(ctx, `SELECT token FROM v2_user WHERE id=42`).Scan(&token); err != nil || token != "unchanged-subscription" {
		t.Fatalf("legacy user changed: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM v2_subscribe_access_log WHERE user_id=42`).Scan(&oldRows); err != nil || oldRows != 1 {
		t.Fatalf("legacy statistics changed: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema=current_schema() AND table_name LIKE 'v2_dns_%'`).Scan(&dnsTables); err != nil || dnsTables != 10 {
		t.Fatalf("DNS schema incomplete: %d %v", dnsTables, err)
	}
	service := &DBService{db: db, dnsFailoverSchemaOK: true}
	probe, err := service.CreateDNSProbe(ctx, DNSProbeCreateRequest{Name: "isolated-test"})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := service.AuthenticateDNSProbe(ctx, probe.Secret)
	if err != nil || identity.ID != probe.Probe.ID {
		t.Fatalf("probe authentication failed: %v", err)
	}
	request := validDNSFailoverRuleSaveRequest()
	request.ID = nil
	request.Enabled = false
	request.AutoFailback = false
	request.ProbeIDs = []int64{probe.Probe.ID}
	rule, err := service.SaveDNSFailoverRule(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if rule.Enabled || rule.AutoFailback {
		t.Fatal("saving disabled rule must not enable automation")
	}
	if tasks, err := service.ListDNSProbeTasks(ctx, probe.Probe.ID); err != nil || len(tasks) != 0 {
		t.Fatalf("disabled rule leaked tasks: %v %v", tasks, err)
	}
	if _, err := service.SetDNSFailoverRuleEnabled(ctx, rule.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := service.HeartbeatDNSProbe(ctx, probe.Probe.ID, DNSProbeHeartbeatRequest{Version: "test", Arch: "amd64", PublicIP: "192.0.2.20"}); err != nil {
		t.Fatal(err)
	}
	tasks, err := service.ListDNSProbeTasks(ctx, probe.Probe.ID)
	enabledTargets := 0
	for _, target := range rule.Targets {
		if target.Enabled {
			enabledTargets++
		}
	}
	if err != nil || len(tasks) != enabledTargets || len(tasks) == 0 {
		t.Fatalf("probe task binding mismatch: %v %v", tasks, err)
	}
	success, latency := true, int64(12)
	report := DNSProbeResultsRequest{Results: []DNSProbeResult{{ResultID: "isolated-1", TargetID: tasks[0].TargetID, Success: &success, LatencyMS: &latency, ResolvedIP: "192.0.2.1"}}}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := service.ReportDNSProbeResults(ctx, probe.Probe.ID, report); err != nil {
			t.Fatal(err)
		}
	}
	var streak int
	if err := db.QueryRowContext(ctx, `SELECT consecutive_success FROM v2_dns_probe_target_state WHERE probe_id=$1 AND target_id=$2`, probe.Probe.ID, tasks[0].TargetID).Scan(&streak); err != nil || streak != 1 {
		t.Fatalf("duplicate report affected streak: %d %v", streak, err)
	}
	if _, err := service.GetDNSFailoverStatus(ctx, rule.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetDNSProbeEnabled(ctx, probe.Probe.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AuthenticateDNSProbe(ctx, probe.Secret); !errors.Is(err, ErrDNSProbeUnauthorized) {
		t.Fatalf("revoked probe remains authorized: %v", err)
	}
	if _, err := service.SetDNSProbeEnabled(ctx, probe.Probe.ID, true); err != nil {
		t.Fatal(err)
	}
	var staleStates int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM v2_dns_probe_target_state WHERE probe_id=$1`, probe.Probe.ID).Scan(&staleStates); err != nil || staleStates != 0 {
		t.Fatalf("reactivated probe retains stale results: %d %v", staleStates, err)
	}
	if _, err := service.SetDNSFailoverRuleEnabled(ctx, rule.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := service.runDNSFailoverCycle(ctx); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-4 * 24 * time.Hour).Unix()
	if _, err := db.ExecContext(ctx, `INSERT INTO v2_dns_failover_event (group_id,event_type,notified_at,created_at) VALUES ($1,'test',NULL,$2),($1,'test',$2,$2)`, rule.ID, oldTime); err != nil {
		t.Fatal(err)
	}
	if err := service.cleanupDNSFailoverRetention(ctx); err != nil {
		t.Fatal(err)
	}
	var pending, delivered int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE notified_at IS NULL),count(*) FILTER (WHERE notified_at IS NOT NULL) FROM v2_dns_failover_event WHERE event_type='test'`).Scan(&pending, &delivered); err != nil || pending != 1 || delivered != 0 {
		t.Fatalf("retention must preserve pending notifications: %d %d %v", pending, delivered, err)
	}
	if _, err := service.DeleteDNSFailoverRule(ctx, rule.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.DeleteDNSProbe(ctx, probe.Probe.ID); err != nil {
		t.Fatal(err)
	}
}
