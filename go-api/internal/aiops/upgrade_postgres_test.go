package aiops

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"forest/go-api/internal/admin"
	"forest/go-api/internal/config"
	"forest/go-api/internal/platform/postgres"
)

// All install SQL and mutations are restricted to a fresh disposable schema.
func TestPostgresAIUpgradeAndOperationalFlow(t *testing.T) {
	dsn := os.Getenv("DNS_FAILOVER_TEST_DSN")
	if dsn == "" {
		t.Skip("dedicated test DSN required")
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	root, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	schema := fmt.Sprintf("ai_upgrade_%d", time.Now().UnixNano())
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
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	installer, err := os.ReadFile("../../../database/install.pgsql.sql")
	if err != nil {
		t.Fatal(err)
	}
	exec(string(installer))
	if err = postgres.EnsureNodeAddressSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err = postgres.EnsureDNSFailoverSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO v2_user(id,email,password,uuid,token,is_admin,is_staff,created_at,updated_at) VALUES
 (1,'admin@example.test','hash','u1','t1',1,0,1,1),(2,'staff@example.test','hash','u2','t2',0,1,1,1),(3,'user@example.test','hash','u3','t3',0,0,1,1);
 INSERT INTO v2_server_group(id,name,created_at,updated_at) VALUES(1,'legacy',1,1);
 INSERT INTO v2_server_vmess(id,group_id,name,host,port,server_port,rate,network,"show",created_at,updated_at) VALUES(7,'[1]','legacy','base.example','443',443,'1','tcp',1,1,1);
 INSERT INTO v2_node_address_group(id,name,created_at,updated_at) VALUES(1,'addresses',1,1);
 INSERT INTO v2_node_address_binding(address_group_id,server_type,server_id,created_at,updated_at) VALUES(1,'vmess',7,1,1);
 INSERT INTO v2_node_address_rule(id,group_id,host,match_user_id_ranges,created_at,updated_at) VALUES(1,1,'range.example','["10-100"]',1,1);
 INSERT INTO v2_insider_rule(id,host,match_user_ids,created_at,updated_at) VALUES(1,'inside.example','["42"]',1,1);
 INSERT INTO v2_runtime_kv(k,v,expire_at,created_at,updated_at) VALUES('legacy-key','legacy-value',0,1,1)`)
	snapshot := func() map[string]string {
		t.Helper()
		out := map[string]string{}
		for _, table := range []string{"v2_user", "v2_server_vmess", "v2_node_address_group", "v2_node_address_rule", "v2_node_address_binding", "v2_insider_rule", "v2_runtime_kv"} {
			var raw string
			if err := db.QueryRowContext(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::TEXT),'[]'::JSONB)::TEXT FROM `+table+` t`).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			out[table] = raw
		}
		return out
	}
	before := snapshot()
	panel := admin.NewDBService(config.Config{}, db)
	s := NewService(config.Config{AppKey: "upgrade-fixture-encryption-key"}, db, panel)
	defer s.Close()
	cfg, err := s.GetConfig(ctx, 1)
	if err != nil || cfg.Enabled || cfg.HasAPIKey {
		t.Fatal("default config", cfg, err)
	}
	// Repeated initialization is additive and preserves existing business rows.
	second := NewService(config.Config{AppKey: "upgrade-fixture-encryption-key"}, db, panel)
	if err = second.ensureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	second.Close()
	if !reflect.DeepEqual(before, snapshot()) {
		t.Fatal("AI initialization changed legacy business data")
	}
	var requests atomic.Int64
	var writeMode atomic.Bool
	var stallMode atomic.Bool
	stalled := make(chan struct{}, 1)
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer fixture-ai-secret" {
			t.Error("provider authorization")
		}
		var req completionRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			t.Error("provider JSON")
			return
		}
		if strings.Contains(fmt.Sprint(req.Messages), "hash") {
			t.Error("business password sent to model")
		}
		hasTool := false
		for _, m := range req.Messages {
			if m.Role == "user" && (m.Content == "读取入口" || m.Content == "关闭QA节点" || m.Content == "停止QA") {
				hasTool = false
			}
			hasTool = hasTool || m.Role == "tool"
		}
		w.Header().Set("Content-Type", "text/event-stream")
		if stallMode.Load() {
			fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"处理中\"},\"finish_reason\":null}]}\n\n")
			w.(http.Flusher).Flush()
			stalled <- struct{}{}
			<-r.Context().Done()
			return
		}
		if !hasTool && writeMode.Load() {
			chunk := map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"tool_calls": []any{map[string]any{"index": 0, "id": "write-node", "type": "function", "function": map[string]any{"name": "propose_node_change", "arguments": `{"node_type":"vmess","node_id":7,"changes":{"show":0},"reason":"full-access QA"}`}}}}, "finish_reason": "tool_calls"}}}
			raw, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", raw)
		} else if !hasTool {
			fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"id\":\"read-entry\",\"type\":\"function\",\"function\":{\"name\":\"entry_health\",\"arguments\":\"{}\"}}]},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\ndata: [DONE]\n\n")
		} else {
			fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"已读取实际入口及ID范围\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
		}
	}))
	defer relay.Close()
	cfg, err = s.SaveConfig(ctx, 1, ConfigSaveRequest{Enabled: true, BaseURL: relay.URL, Models: []string{"fixture-model"}, APIKey: "fixture-ai-secret"})
	if err != nil || !cfg.HasAPIKey {
		t.Fatal(cfg, err)
	}
	var cipher string
	if err = db.QueryRow(`SELECT api_key_cipher FROM v2_ai_config`).Scan(&cipher); err != nil || strings.Contains(cipher, "fixture-ai-secret") {
		t.Fatal("unencrypted model key", err)
	}
	if _, err = s.SaveConfig(ctx, 2, ConfigSaveRequest{}); !errors.Is(err, ErrForbidden) {
		t.Fatal("staff config write", err)
	}
	if _, err = s.GetConfig(ctx, 3); !errors.Is(err, ErrForbidden) {
		t.Fatal("ordinary user AI access", err)
	}
	session, err := s.CreateSession(ctx, 1, CreateSessionRequest{Title: "upgrade QA", Model: "fixture-model"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.GetSession(ctx, 2, session.ID); !errors.Is(err, ErrForbidden) && !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-session staff access", err)
	}
	call := func(name, args string) ToolOutcome {
		t.Helper()
		out, err := s.callTool(ctx, 1, session.ID, ToolCall{ID: "fixture-" + name, Function: ToolFunction{Name: name, Arguments: args}})
		if err != nil {
			t.Fatal(name, err)
		}
		return out
	}
	health := call("entry_health", `{}`)
	for _, host := range []string{"base.example", "range.example", "inside.example"} {
		if !strings.Contains(health.Content, host) {
			t.Fatal("missing actual entry", health.Content)
		}
	}
	exec(`UPDATE v2_server_vmess SET "show"=0 WHERE id=7`)
	health = call("entry_health", `{}`)
	if strings.Contains(health.Content, "base.example") || strings.Contains(health.Content, "range.example") {
		t.Fatal("disabled node leaked", health.Content)
	}
	exec(`UPDATE v2_server_vmess SET "show"=1 WHERE id=7`)
	// Standard mode must wait for approval and reject a stale configuration.
	session, err = s.SetAccessMode(ctx, 1, AccessModeRequest{ID: session.ID, Mode: "standard", ExpectedVersion: &session.AccessVersion})
	if err != nil {
		t.Fatal(err)
	}
	propose := func(id string, show int) Action {
		t.Helper()
		payload, _ := json.Marshal(nodePayload{NodeType: "vmess", NodeID: 7, Changes: nodePatch{Show: &show}})
		a, err := s.proposeAction(ctx, 1, session.ID, id, actionSpec{Kind: "node_change", TargetID: 7, TargetType: "vmess", Payload: payload, Reason: "QA switch"})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	a := propose("node-stale", 0)
	exec(`UPDATE v2_server_vmess SET name='changed concurrently' WHERE id=7`)
	if _, err = s.ApproveAction(ctx, 1, session.ID, a.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("stale approval accepted", err)
	}
	if _, err = s.RejectAction(ctx, 1, session.ID, a.ID); err != nil {
		t.Fatal(err)
	}
	a = propose("node-approve", 0)
	var show int
	db.QueryRow(`SELECT "show" FROM v2_server_vmess WHERE id=7`).Scan(&show)
	if show != 1 || a.Status != "pending" {
		t.Fatal("proposal wrote before approval")
	}
	done, err := s.ApproveAction(ctx, 1, session.ID, a.ID)
	if err != nil || done.Status != "succeeded" {
		t.Fatal(done, err)
	}
	db.QueryRow(`SELECT "show" FROM v2_server_vmess WHERE id=7`).Scan(&show)
	if show != 0 {
		t.Fatal("approved change missing")
	}
	if _, err = s.ApproveAction(ctx, 1, session.ID, a.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("approval replay accepted", err)
	}
	exec(`UPDATE v2_server_vmess SET "show"=1 WHERE id=7`)
	k, err := s.SaveKnowledge(ctx, 1, KnowledgeSaveRequest{Title: "入口规则", Summary: "优先级说明", Content: "内鬼管理优先于节点地址，最后使用节点原地址。", Status: "active", Category: "network"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SaveKnowledge(ctx, 1, KnowledgeSaveRequest{ID: k.ID, Title: k.Title, Content: "new content", Status: "active", Category: "network", ExpectedVersion: new(int64)}); !errors.Is(err, ErrConflict) && !errors.Is(err, ErrValidation) {
		t.Fatal("knowledge stale version", err)
	}
	// Exercise the actual async chat, streamed provider, tool round and persisted history.
	req := SendMessageRequest{SessionID: session.ID, Model: "fixture-model", Content: "读取入口", RequestID: "upgrade-chat-0001"}
	sent, err := s.SendMessage(ctx, 1, req)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(12 * time.Second)
	for {
		detail, e := s.GetSession(ctx, 1, session.ID)
		if e != nil {
			t.Fatal(e)
		}
		if detail.Session.Status != "running" {
			raw, _ := json.Marshal(detail)
			if !strings.Contains(string(raw), "已读取实际入口及ID范围") {
				t.Fatal("chat flow", string(raw))
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("chat did not finish")
		}
		time.Sleep(20 * time.Millisecond)
	}
	replay, err := s.SendMessage(ctx, 1, req)
	if err != nil || replay.Turn.ID != sent.Turn.ID {
		t.Fatal("request idempotency", replay, err)
	}
	if requests.Load() != 2 {
		t.Fatal("unexpected provider rounds", requests.Load())
	}
	session, err = s.SetAccessMode(ctx, 1, AccessModeRequest{ID: session.ID, Mode: "full", ExpectedVersion: &session.AccessVersion})
	if err != nil {
		t.Fatal(err)
	}
	writeMode.Store(true)
	_, err = s.SendMessage(ctx, 1, SendMessageRequest{SessionID: session.ID, Model: "fixture-model", Content: "关闭QA节点", RequestID: "upgrade-full-0001", AccessMode: "full", AccessVersion: &session.AccessVersion})
	if err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(12 * time.Second)
	for {
		detail, e := s.GetSession(ctx, 1, session.ID)
		if e != nil {
			t.Fatal(e)
		}
		if detail.Session.Status != "running" {
			actions, e := s.ListActions(ctx, 1, session.ID)
			if e != nil {
				t.Fatal(e)
			}
			found := false
			for _, a := range actions {
				found = found || a.Status == "succeeded" && a.ApprovalMode == "full_access"
			}
			if !found {
				t.Fatal("full access did not execute", actions, detail)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("full access timeout")
		}
		time.Sleep(20 * time.Millisecond)
	}
	db.QueryRow(`SELECT "show" FROM v2_server_vmess WHERE id=7`).Scan(&show)
	if show != 0 {
		t.Fatal("full access mutation missing")
	}
	exec(`UPDATE v2_server_vmess SET "show"=1 WHERE id=7`)
	stallMode.Store(true)
	_, err = s.SendMessage(ctx, 1, SendMessageRequest{SessionID: session.ID, Model: "fixture-model", Content: "停止QA", RequestID: "upgrade-stop-0001", AccessMode: "full", AccessVersion: &session.AccessVersion})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-stalled:
	case <-time.After(5 * time.Second):
		t.Fatal("stalled provider not entered")
	}
	if err = s.StopSession(ctx, 1, session.ID); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		detail, e := s.GetSession(ctx, 1, session.ID)
		if e != nil {
			t.Fatal(e)
		}
		if detail.Session.Status != "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stop did not cancel provider")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, name := range []string{"monitor_run", "entry_probe_run", "propose_entry_split", "sql"} {
		if toolCapabilityAllowed(name) {
			t.Fatal("unsupported tool exposed", name)
		}
	}
}
