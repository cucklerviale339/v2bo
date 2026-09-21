package subscribeguard

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresUpgradeAndGuardLifecycle(t *testing.T) {
	dsn := os.Getenv("SUBSCRIBE_GUARD_TEST_DSN")
	if dsn == "" {
		t.Skip("SUBSCRIBE_GUARD_TEST_DSN not set")
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
	schema := fmt.Sprintf("subscribe_guard_test_%d", time.Now().UnixNano())
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
	db.SetMaxOpenConns(8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = db.Exec(`CREATE TABLE v2_user (id BIGINT PRIMARY KEY, email TEXT, banned INTEGER DEFAULT 0, is_admin INTEGER DEFAULT 0, is_staff INTEGER DEFAULT 0);
INSERT INTO v2_user (id,email) VALUES (42, 'guard-test@example.com'), (43, 'other@example.com');
CREATE TABLE v2_subscribe_access_log (id BIGINT, user_id BIGINT, client_ip TEXT, accessed_at BIGINT);
INSERT INTO v2_subscribe_access_log VALUES (1, 42, '192.0.2.2', 100)`)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(db, "test-key")
	for count := 0; count < 2; count++ {
		if err := store.Ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	policy, err := store.Policy(ctx)
	if err != nil || policy.Mode != "off" || policy.Revision != 0 {
		t.Fatalf("unsafe upgrade defaults: %+v %v", policy, err)
	}
	var oldCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM v2_subscribe_access_log WHERE user_id = 42 AND accessed_at = 100").Scan(&oldCount); err != nil || oldCount != 1 {
		t.Fatal("legacy history changed", err)
	}
	policy.Mode = "observe"
	policy.Rules = []Rule{{Kind: "token_block", Token: "do-not-store-this-token"}}
	policy.TokenBlacklist = []string{"editable-private-token"}
	saved, err := store.Save(ctx, policy, 7)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision != 1 || saved.Rules[0].Token != "" {
		t.Fatal("invalid saved policy")
	}
	if _, err := store.Save(ctx, policy, 8); !errors.Is(err, ErrConflict) {
		t.Fatalf("lost-update protection failed: %v", err)
	}
	var storedPolicy, auditPolicy string
	if err := db.QueryRow("SELECT policy::text FROM v2_subscribe_guard_config").Scan(&storedPolicy); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT policy::text FROM v2_subscribe_guard_audit").Scan(&auditPolicy); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(storedPolicy+auditPolicy, "do-not-store-this-token") || strings.Contains(storedPolicy+auditPolicy, "editable-private-token") || strings.Contains(auditPolicy, "encrypted_tokens") {
		t.Fatal("raw credential persisted")
	}
	otherInstance := NewStore(db, "test-key")
	latest, err := otherInstance.Policy(ctx)
	if err != nil || latest.Revision != 1 || latest.Mode != "observe" {
		t.Fatal("other instance did not see policy", err)
	}
	if len(latest.TokenBlacklist) != 1 || latest.TokenBlacklist[0] != "editable-private-token" || latest.Reason("", Fingerprint("test-key", "editable-private-token"), "", time.Now()) != "token" {
		t.Fatal("encrypted list did not survive reload")
	}
	var allowed atomic.Int64
	var wait sync.WaitGroup
	for index := 0; index < 40; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			instance := store
			if index%2 == 0 {
				instance = otherInstance
			}
			ok, err := instance.Rate(ctx, "concurrency", 20)
			if err != nil {
				t.Error(err)
				return
			}
			if ok {
				allowed.Add(1)
			}
		}(index)
	}
	wait.Wait()
	if allowed.Load() != 20 {
		t.Fatalf("cross-instance limit admitted %d, expected 20", allowed.Load())
	}
	if ok, err := NewStore(db, "test-key").Rate(ctx, "concurrency", 20); err != nil || ok {
		t.Fatalf("restart reset rate counter: %v %v", ok, err)
	}
	workerDone := make(chan struct{})
	go func() { store.Run(ctx); close(workerDone) }()
	defer func() { cancel(); <-workerDone }()
	store.Record(Event{IP: "192.0.2.1", UA: "Clash", TokenHash: Fingerprint("test-key", "one"), Endpoint: "subscribe", Mode: "observe", Reason: "ua", UserID: 42, Time: time.Now().Unix(), Status: 200})
	store.Record(Event{IP: "192.0.2.3", UA: "curl", Endpoint: "subscribe", Mode: "enforce", Reason: "ip", Blocked: true, Time: time.Now().Unix(), Status: 403, CrawlerUA: true})
	deadline := time.Now().Add(5 * time.Second)
	for {
		result, err := store.Events(ctx, Filter{Limit: 50})
		if err != nil {
			t.Fatal(err)
		}
		if result["total"].(int64) == 2 {
			items := result["data"].([]Event)
			if len(items) != 2 || items[0].UserID != 0 || items[1].Email != "guard-test@example.com" {
				t.Fatalf("unknown users lost: %+v", items)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("events not persisted")
		}
		time.Sleep(10 * time.Millisecond)
	}
	result, err := store.Events(ctx, Filter{Keyword: "guard-test@", Outcome: "matched", Limit: 50})
	if err != nil || result["total"].(int64) != 1 {
		t.Fatalf("email/outcome filter failed: %+v %v", result, err)
	}
	result, err = store.Events(ctx, Filter{Keyword: "%", Limit: 50})
	if err != nil || result["total"].(int64) != 0 {
		t.Fatalf("wildcard search widened scope: %+v %v", result, err)
	}
	audit, err := store.Audit(ctx)
	if err != nil || len(audit) != 1 || audit[0]["admin_id"] != int64(7) {
		t.Fatal("audit not atomic", err)
	}
	raw, _ := json.Marshal(audit)
	if strings.Contains(string(raw), "do-not-store") {
		t.Fatal("audit leaks token")
	}
	summary, err := store.Analytics(ctx, 0)
	if err != nil || summary["total"] != float64(2) || summary["blocked"] != float64(1) || summary["allowed"] != float64(1) {
		t.Fatalf("summary: %+v %v", summary, err)
	}
	summary, err = store.Analytics(ctx, 42)
	if err != nil || summary["total"] != float64(1) {
		t.Fatalf("user summary: %+v %v", summary, err)
	}
	users, err := store.Users(ctx, "CURL", "count", 1, 20)
	if err != nil || users["total"] != int64(0) || users["unresolved"] != int64(1) || users["matched"] != int64(1) {
		t.Fatalf("unknown UA: %+v %v", users, err)
	}
	users, err = store.Users(ctx, "%", "count", 1, 20)
	if err != nil || users["matched"] != int64(0) {
		t.Fatalf("UA wildcard interpreted: %+v %v", users, err)
	}
	result, err = store.Events(ctx, Filter{UserID: 42, UA: "clash", Limit: 50})
	if err != nil || result["total"] != int64(1) {
		t.Fatalf("user+UA filter: %+v %v", result, err)
	}
	_, err = db.Exec(`INSERT INTO v2_subscribe_guard_event (user_id,client_ip,user_agent,token_hash,endpoint,mode,reason,blocked,status_code,accessed_at)
VALUES (42,'192.0.2.1','Clash','','subscribe','off','',false,200,$1),
(42,'192.0.2.1','Clash','','subscribe','off','',false,200,$1),
(43,'192.0.2.5','Clash','','subscribe','off','',false,200,$1),
(43,'192.0.2.6','Clash','','subscribe','enforce','token_rate',true,429,$1)`, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		sort           string
		page, expected int64
	}{{"count", 1, 42}, {"ip_count", 1, 43}, {"count", 2, 43}} {
		users, err = store.Users(ctx, "clash", test.sort, test.page, 1)
		if err != nil {
			t.Fatal(err)
		}
		rows := users["data"].([]map[string]any)
		if users["total"] != int64(2) || len(rows) != 1 || rows[0]["user_id"] != float64(test.expected) {
			t.Fatalf("ranking: %+v", users)
		}
	}
	result, err = store.Events(ctx, Filter{UserID: 43, UA: "clash", Outcome: "blocked", Limit: 50})
	if err != nil || result["total"] != int64(1) {
		t.Fatalf("combined filter: %+v %v", result, err)
	}
	summary, err = store.Analytics(ctx, 43)
	if err != nil || summary["ip_count"] != float64(2) || summary["rate_limited"] != float64(1) {
		t.Fatalf("rank stats: %+v %v", summary, err)
	}
	_, err = db.Exec(`INSERT INTO v2_subscribe_guard_event (user_id,client_ip,user_agent,token_hash,endpoint,mode,reason,blocked,status_code,accessed_at,crawler_ua,ua_whitelisted)
VALUES (42,'192.0.2.9','curl/8','','subscribe','off','',false,200,$1,true,false),
(42,'192.0.2.8','python','','subscribe','enforce','crawler_ua',true,403,$1,true,false),
(43,'192.0.2.7','trusted curl','','subscribe','enforce','',false,200,$1,true,true)`, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	crawlers, err := store.CrawlerUsers(ctx, 1, 20)
	if err != nil || crawlers["total"] != int64(2) || crawlers["matched"] != int64(4) || crawlers["unresolved"] != int64(1) {
		t.Fatalf("crawler users: %+v %v", crawlers, err)
	}
	crawlerRows := crawlers["data"].([]map[string]any)
	if crawlerRows[0]["user_id"] != float64(42) || crawlerRows[0]["crawler_blocked"] != float64(1) || crawlerRows[1]["whitelisted"] != float64(1) {
		t.Fatalf("wrong crawler counts: %+v", crawlerRows)
	}
	result, err = store.Events(ctx, Filter{UserID: 42, CrawlerOnly: true, Limit: 50})
	if err != nil || result["total"] != int64(2) || result["blocked"] != int64(1) {
		t.Fatalf("crawler filter: %+v %v", result, err)
	}
	items := result["data"].([]Event)
	if items[0].Email != "guard-test@example.com" || !items[0].CrawlerUA {
		t.Fatalf("crawler details: %+v", items)
	}
	result, err = store.Events(ctx, Filter{UserID: 42, CrawlerOnly: true, Before: items[0].ID, Limit: 50})
	if err != nil || len(result["data"].([]Event)) != 1 {
		t.Fatalf("crawler pagination: %+v %v", result, err)
	}
}
