package subscribeguard

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

func testMonitoringLifecycle(t *testing.T, db *sql.DB, store *Store) {
	t.Helper()
	ctx := context.Background()
	status, err := store.MonitoringStatus(ctx)
	if err != nil || !status.Ready || !status.Enabled || !status.ForceOff {
		t.Fatalf("status: %+v %v", status, err)
	}
	if err := store.SetIPLookup(ctx, false, status.Revision, 7); err != nil {
		t.Fatal(err)
	}
	if err := store.SetIPLookup(ctx, true, status.Revision, 8); !errors.Is(err, ErrConflict) {
		t.Fatal("lost update not rejected", err)
	}
	status, err = store.MonitoringStatus(ctx)
	if err != nil || status.Enabled {
		t.Fatal("switch not saved", err)
	}
	if count, err := store.RetryIPLookups(ctx); !errors.Is(err, ErrMonitorUnavailable) || count != 0 {
		t.Fatal("force off bypassed")
	}
	t.Setenv("SUBSCRIBE_IP_INTELLIGENCE_OFF", "0")
	if err := store.SetIPLookup(ctx, true, status.Revision, 7); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()/3600*3600 + 100
	_, err = db.Exec(`UPDATE v2_subscribe_monitor_control SET snapshot_next=0;
INSERT INTO v2_subscribe_ip_intelligence(client_ip,last_seen,next_attempt,profile) VALUES
('9.9.9.9',extract(epoch from now())::bigint,extract(epoch from now())::bigint+3600,'{"geo_state":"unavailable","risk_state":"unavailable"}')`)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := store.RetryIPLookups(ctx); err != nil || count != 1 {
		t.Fatal("retry not queued", count, err)
	}
	var retryAt int64
	if err := db.QueryRow(`SELECT next_attempt FROM v2_subscribe_ip_intelligence WHERE client_ip='9.9.9.9'`).Scan(&retryAt); err != nil || retryAt > time.Now().Unix() {
		t.Fatal("retry deadline", err)
	}
	_, err = db.Exec(`INSERT INTO v2_subscribe_guard_event(user_id,client_ip,user_agent,token_hash,endpoint,mode,reason,blocked,status_code,accessed_at)
SELECT 42,'192.0.2.'||series,'curl','snapshot-subject','subscribe','off','',false,200,$1 FROM generate_series(1,8) series`, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.captureRiskHistory(ctx, now); err != nil {
		t.Fatal(err)
	}
	if err := store.captureRiskHistory(ctx, now+1); err != nil {
		t.Fatal(err)
	}
	filter := RiskHistoryFilter{Keyword: "snapshot-subject", Current: 1, PageSize: 20}
	history, err := store.RiskHistory(ctx, filter)
	if err != nil || history.Total != 1 || history.Data[0].Profile.Score < 60 {
		t.Fatalf("snapshot: %+v %v", history, err)
	}
	entry := history.Data[0]
	if err := store.ReviewRisk(ctx, entry.ID, entry.Revision, 7, "false_positive", "已核对正常使用"); err != nil {
		t.Fatal(err)
	}
	if err := store.ReviewRisk(ctx, entry.ID, entry.Revision, 8, "handled", "覆盖"); !errors.Is(err, ErrConflict) {
		t.Fatal("review overwritten", err)
	}
	if err := store.captureRiskHistory(ctx, now+60); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM v2_subscribe_guard_event WHERE token_hash='snapshot-subject'`); err != nil {
		t.Fatal(err)
	}
	history, err = store.RiskHistory(ctx, filter)
	if err != nil || history.Total != 1 || history.Data[0].Status != "false_positive" || history.Data[0].ReviewedBy != 7 || history.Data[0].Profile.Score != entry.Profile.Score {
		t.Fatal("history or decision lost", err)
	}
	testRiskReviewCooldown(t, db, store)
	testIPLeaseRetry(t, db, store)
	testAnalyticsSurvivesIntelligenceTimeout(t, db, store)
	if _, err := db.Exec(`DROP TABLE v2_subscribe_ip_intelligence; CREATE TABLE v2_subscribe_ip_intelligence(client_ip VARCHAR(64))`); err != nil {
		t.Fatal(err)
	}
	store.monitorReady.Store(true)
	if _, err := store.Risks(ctx, RiskFilter{Current: 1, PageSize: 20}); err != nil {
		t.Fatal("runtime optional-schema failure broke risk list", err)
	}
	if err := store.EnsureMonitoring(ctx); err == nil || store.monitorReady.Load() {
		t.Fatal("broken optional schema considered ready")
	}
	if err := store.Ensure(ctx); err != nil {
		t.Fatal("optional schema failure disabled core guard", err)
	}
	policy, err := store.Policy(ctx)
	if err != nil || policy.Mode != "observe" {
		t.Fatal("core policy unavailable", err)
	}
	if _, err := store.RiskEvents(ctx, "", 42); err != nil {
		t.Fatal("request details blocked by optional schema", err)
	}
	if _, err := store.Analytics(ctx, 42); err != nil {
		t.Fatal("statistics blocked by optional schema", err)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { store.Run(workerCtx); close(done) }()
	defer func() { cancel(); <-done }()
	store.Record(Event{IP: "192.0.2.200", UA: "Clash", UserID: 42, TokenHash: "isolation-test", Endpoint: "subscribe", Mode: "off", Status: 200, Time: now})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		result, err := store.Events(ctx, Filter{Keyword: "192.0.2.200", Limit: 50})
		if err != nil {
			t.Fatal(err)
		}
		if result["total"] == int64(1) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("optional initialization failure stopped event recording")
}

func testAnalyticsSurvivesIntelligenceTimeout(t *testing.T, db *sql.DB, store *Store) {
	t.Helper()
	baseline, err := store.Analytics(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err := lock.Exec(`LOCK TABLE v2_subscribe_ip_intelligence IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	result, err := store.Analytics(ctx, 42)
	if err != nil {
		t.Fatalf("optional intelligence timeout broke core analytics: %v", err)
	}
	if ctx.Err() == nil {
		t.Fatal("test did not exercise intelligence lock timeout")
	}
	if result["total"] != baseline["total"] {
		t.Fatal("core totals changed during intelligence failure")
	}
	for _, key := range []string{"ips", "uas", "tokens", "reasons"} {
		if len(result[key].([]map[string]any)) != len(baseline[key].([]map[string]any)) {
			t.Fatalf("missing core analytics: %s", key)
		}
	}
	for _, item := range result["ips"].([]map[string]any) {
		profile := item["intelligence"].(*IPIntelligence)
		if profile.GeoState != "unavailable" || profile.RiskState != "unavailable" {
			t.Fatal("failed lookup presented as usable intelligence")
		}
	}
}
