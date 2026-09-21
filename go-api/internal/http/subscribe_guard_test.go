package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"forest/go-api/internal/admin"
	"forest/go-api/internal/config"
	"forest/go-api/internal/session"
	"forest/go-api/internal/subscribeguard"
	"forest/go-api/internal/user"
)

type guardTestStore struct {
	policy    subscribeguard.Policy
	events    []subscribeguard.Event
	err       error
	rateErr   error
	denyRate  bool
	saveAdmin int64
}

func (store *guardTestStore) Policy(context.Context) (subscribeguard.Policy, error) {
	return store.policy, store.err
}
func (store *guardTestStore) Save(_ context.Context, policy subscribeguard.Policy, adminID int64) (subscribeguard.Policy, error) {
	store.saveAdmin = adminID
	store.policy = policy
	return policy, nil
}
func (store *guardTestStore) Rate(context.Context, string, int64) (bool, error) {
	return !store.denyRate, store.rateErr
}
func (store *guardTestStore) Record(event subscribeguard.Event) {
	store.events = append(store.events, event)
}
func (store *guardTestStore) Events(context.Context, subscribeguard.Filter) (map[string]any, error) {
	return map[string]any{"data": store.events}, nil
}
func (store *guardTestStore) Audit(context.Context) ([]map[string]any, error) { return nil, nil }
func (store *guardTestStore) Analytics(context.Context, int64) (map[string]any, error) {
	return map[string]any{"total": 1}, store.err
}
func (store *guardTestStore) Users(context.Context, string, string, int64, int64) (map[string]any, error) {
	return map[string]any{"data": []any{}}, store.err
}
func (store *guardTestStore) CrawlerUsers(context.Context, int64, int64) (map[string]any, error) {
	return map[string]any{"data": []any{}}, store.err
}

type guardOnceUser struct {
	fakeUserService
	authCalls    int
	peekCalls    int
	serverCalls  int
	subscribeErr error
}

func (service *guardOnceUser) PeekClientUserID(_ context.Context, token string) (int64, error) {
	service.peekCalls++
	if token == "invalid" {
		return 0, user.ErrClientTokenInvalid
	}
	return 42, nil
}

func (service *guardOnceUser) ResolveClientUserID(_ context.Context, token string) (int64, error) {
	service.authCalls++
	service.lastClientToken = token
	if service.authCalls > 1 {
		return 0, errors.New("one-time token consumed twice")
	}
	return 42, nil
}
func (service *guardOnceUser) Servers(context.Context, int64, string) ([]map[string]any, error) {
	service.serverCalls++
	return service.servers, nil
}
func (service *guardOnceUser) Subscribe(context.Context, int64) (user.Subscribe, error) {
	return service.subscribe, service.subscribeErr
}

func TestGuardModesPreserveSubscriptionAndOneTimeTokens(t *testing.T) {
	for _, mode := range []string{"off", "observe", "enforce"} {
		for _, target := range []string{"/api/v1/client/subscribe?token=single-use", "/s/single-use"} {
			t.Run(mode+target, func(t *testing.T) {
				store := &guardTestStore{policy: subscribeguard.DefaultPolicy()}
				store.policy.Mode = mode
				store.policy.BlockEmptyUA = true
				service := &guardOnceUser{}
				router := NewRouter(config.Config{AppKey: "key", SubscribePath: "/s"}, WithSubscribeGuard(store), WithUserService(service))
				recorder := httptest.NewRecorder()
				router.ServeHTTP(recorder, httptest.NewRequest("GET", target, nil))
				if mode == "enforce" {
					if recorder.Code != 403 || service.authCalls != 0 || service.serverCalls != 0 {
						t.Fatalf("not blocked before auth: %d %+v", recorder.Code, service)
					}
				} else if recorder.Code != 200 || service.authCalls != 1 || service.lastClientToken != "single-use" {
					t.Fatalf("changed subscription: %d %+v", recorder.Code, service)
				}
				if mode == "off" {
					if len(store.events) != 1 || store.events[0].Reason != "" || store.events[0].UserID != 42 || store.events[0].Blocked {
						t.Fatal("off mode must log without checking rules")
					}
				}
				if len(store.events) != 1 || store.events[0].Status != recorder.Code || store.events[0].Endpoint != "subscribe" {
					t.Fatalf("invalid event: %+v", store.events)
				}
				if mode == "observe" && (store.events[0].Blocked || store.events[0].UserID != 42) {
					t.Fatal("observe affected auth")
				}
				raw, _ := json.Marshal(store.events)
				if strings.Contains(string(raw), "single-use") {
					t.Fatal("token leaked into event")
				}
			})
		}
	}
}

func TestGuardDashboardAuthorizationAndAccountSafety(t *testing.T) {
	store := &guardTestStore{policy: subscribeguard.DefaultPolicy()}
	adminService := &fakeAdminService{userInfoDetail: map[string]any{"id": int64(42), "email": "test@example.com", "token": "secret", "password": "secret", "uuid": "secret"}}
	identity := &fakeSessionService{user: &session.Identity{ID: 7, IsAdmin: 1}}
	router := NewRouter(config.Config{AdminPath: "localadmin"}, WithSubscribeGuard(store), WithSessionService(identity), WithAdminService(adminService))
	for _, path := range []string{"stats", "user-rank", "crawler-users", "ua-search?keyword=clash", "user-search?keyword=42", "user-detail?id=42", "set-user-banned"} {
		anonymous := NewRouter(config.Config{AdminPath: "localadmin"}, WithSubscribeGuard(store), WithAdminService(adminService), WithSessionService(&fakeSessionService{authErr: session.ErrUnauthorized}))
		recorder := httptest.NewRecorder()
		method := "GET"
		if path == "set-user-banned" {
			method = "POST"
		}
		anonymous.ServeHTTP(recorder, httptest.NewRequest(method, "/api/v1/localadmin/subscribe-access/guard/"+path, nil))
		if recorder.Code != 403 && recorder.Code != 401 {
			t.Fatalf("anonymous %s: %d", path, recorder.Code)
		}
	}
	for _, path := range []string{"stats", "user-rank", "crawler-users", "ua-search?keyword=clash", "user-search?keyword=42", "user-detail?id=42"} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest("GET", "/api/v1/localadmin/subscribe-access/guard/"+path, nil))
		if recorder.Code != 200 || strings.Contains(recorder.Body.String(), "secret") {
			t.Fatalf("invalid %s: %d %s", path, recorder.Code, recorder.Body.String())
		}
	}
	for _, protected := range []string{"is_admin", "is_staff", "deleted_user", "self", "normal"} {
		info := map[string]any{"id": int64(42), protected: int64(1)}
		id := "42"
		if protected == "self" {
			id = "7"
		}
		adminService.userInfoDetail = info
		adminService.lastUserBannedID = 0
		request := httptest.NewRequest("POST", "/api/v1/localadmin/subscribe-access/guard/set-user-banned", strings.NewReader(`{"id":`+id+`,"banned":1}`))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if protected == "normal" {
			if recorder.Code != 200 || adminService.lastUserBannedID != 42 {
				t.Fatal("normal ban failed")
			}
		} else if recorder.Code != 400 || adminService.lastUserBannedID != 0 {
			t.Fatalf("unsafe ban: %s %d", protected, recorder.Code)
		}
	}
	for _, path := range []string{"user-detail?id=-1", "ua-search", "user-rank?sort=email", "user-rank?current=0"} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest("GET", "/api/v1/localadmin/subscribe-access/guard/"+path, nil))
		if recorder.Code != 400 {
			t.Fatalf("invalid parameters accepted: %s %d", path, recorder.Code)
		}
	}
}

func TestCrawlerDetectionUsersAndIndependentSwitch(t *testing.T) {
	for _, test := range []struct {
		name, mode, token    string
		enabled, whitelist   bool
		status, calls, peeks int
		userID               int64
	}{
		{"off records", "off", "valid", true, false, 200, 1, 0, 42},
		{"switch off records", "enforce", "valid", false, false, 200, 1, 0, 42},
		{"observe records", "observe", "valid", true, false, 200, 1, 0, 42},
		{"block identifies without consuming", "enforce", "single-use", true, false, 403, 0, 1, 42},
		{"invalid remains unknown", "enforce", "invalid", true, false, 403, 0, 1, 0},
		{"whitelist wins", "enforce", "valid", true, true, 200, 1, 0, 42},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &guardTestStore{policy: subscribeguard.DefaultPolicy()}
			store.policy.Mode, store.policy.BlockCrawlerUA = test.mode, test.enabled
			if test.whitelist {
				store.policy.Rules = []subscribeguard.Rule{{Kind: "ua_allow", Value: "curl"}}
			}
			service := &guardOnceUser{}
			router := NewRouter(config.Config{AppKey: "key"}, WithSubscribeGuard(store), WithUserService(service))
			request := httptest.NewRequest("GET", "/api/v1/client/subscribe?token="+test.token, nil)
			request.Header.Set("User-Agent", "CuRL/8.0")
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			if recorder.Code != test.status || service.authCalls != test.calls || service.peekCalls != test.peeks || len(store.events) != 1 {
				t.Fatalf("request changed: %d %+v", recorder.Code, service)
			}
			event := store.events[0]
			if !event.CrawlerUA || event.UserID != test.userID || event.UAWhitelisted != test.whitelist || event.Blocked != (test.status == 403) {
				t.Fatalf("wrong trigger detail: %+v", event)
			}
		})
	}
}

func TestSensitiveModuleNoLongerExposed(t *testing.T) {
	router := NewRouter(config.Config{AdminPath: "localadmin"}, WithSubscribeGuard(&guardTestStore{}), WithAdminService(&fakeAdminService{}), WithSessionService(&fakeSessionService{user: &session.Identity{ID: 7, IsAdmin: 1}}))
	for _, target := range []struct {
		path   string
		status int
	}{{"/api/v1/localadmin/subscribe-access/guard/sensitive", 404}, {"/api/v1/server/UniProxy/sensitive", 410}} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest("GET", target.path, nil))
		if recorder.Code != target.status {
			t.Fatalf("sensitive endpoint active: %s %d", target.path, recorder.Code)
		}
	}
}

func TestGuardCrawlerSwitchMatrixPreservesDelivery(t *testing.T) {
	for _, mode := range []string{"off", "observe", "enforce"} {
		for _, enabled := range []bool{false, true} {
			for _, target := range []string{"/api/v1/client/subscribe?token=single-use", "/s/single-use", "/api/v1/user/server/fetch"} {
				store := &guardTestStore{policy: subscribeguard.DefaultPolicy()}
				store.policy.Mode, store.policy.BlockCrawlerUA = mode, enabled
				service := &guardOnceUser{}
				cfg := config.Config{AppKey: "key", SubscribePath: "/s"}
				identity := &fakeSessionService{user: &session.Identity{ID: 42}}
				baseline := NewRouter(cfg, WithUserService(&guardOnceUser{}), WithSessionService(identity))
				router := NewRouter(cfg, WithSubscribeGuard(store), WithUserService(service), WithSessionService(identity))
				request := httptest.NewRequest("GET", target, nil)
				request.Header.Set("User-Agent", "CuRL/8.0")
				original, guarded := httptest.NewRecorder(), httptest.NewRecorder()
				baseline.ServeHTTP(original, request.Clone(context.Background()))
				router.ServeHTTP(guarded, request)
				blocked := mode == "enforce" && enabled
				if blocked {
					if guarded.Code != 403 || service.authCalls != 0 || service.serverCalls != 0 {
						t.Fatalf("crawler not blocked safely: mode=%s enabled=%t target=%s status=%d", mode, enabled, target, guarded.Code)
					}
				} else if original.Code != 200 || guarded.Code != original.Code || guarded.Body.String() != original.Body.String() {
					t.Fatalf("delivery changed: mode=%s enabled=%t target=%s baseline=%d guarded=%d", mode, enabled, target, original.Code, guarded.Code)
				}
				if len(store.events) != 1 || !store.events[0].CrawlerUA || store.events[0].Blocked != blocked || store.events[0].UserID != 42 || store.events[0].Status != guarded.Code {
					t.Fatalf("missing or inaccurate crawler statistics: mode=%s enabled=%t target=%s events=%+v", mode, enabled, target, store.events)
				}
				if !blocked && target != "/api/v1/user/server/fetch" && (service.authCalls != 1 || service.peekCalls != 0) {
					t.Fatalf("token consumed more than once: %+v", service)
				}
			}
		}
	}
}

func TestGuardStatisticsIndependentOfEnforcement(t *testing.T) {
	for _, mode := range []string{"off", "observe", "enforce"} {
		for _, enabled := range []bool{false, true} {
			store := &guardTestStore{policy: subscribeguard.DefaultPolicy(), denyRate: true}
			store.policy.Mode, store.policy.BlockCrawlerUA = mode, enabled
			store.policy.IPLimit, store.policy.TokenLimit = 1, 1
			identity := &fakeSessionService{user: &session.Identity{ID: 7, IsAdmin: 1}}
			router := NewRouter(config.Config{AdminPath: "localadmin"}, WithSubscribeGuard(store), WithSessionService(identity), WithAdminService(&fakeAdminService{}))
			for _, action := range []string{"stats", "crawler-users", "events?crawler_only=1", "user-rank", "ua-search?keyword=curl"} {
				request := httptest.NewRequest("GET", "/api/v1/localadmin/subscribe-access/guard/"+action, nil)
				request.Header.Set("User-Agent", "curl/8")
				recorder := httptest.NewRecorder()
				router.ServeHTTP(recorder, request)
				if recorder.Code != 200 || !identity.lastRequireAdmin {
					t.Fatalf("statistics unavailable or unprotected: mode=%s enabled=%t action=%s status=%d", mode, enabled, action, recorder.Code)
				}
			}
			if len(store.events) != 0 {
				t.Fatal("admin statistics requests must not pollute subscription statistics")
			}
		}
	}
}

func TestCrawlerSwitchOffPreservesExplicitBlacklist(t *testing.T) {
	for _, rule := range []subscribeguard.Rule{
		{Kind: "ua_block", Value: "curl"},
		{Kind: "token_block", Value: subscribeguard.Fingerprint("key", "single-use")},
		{Kind: "user_block", Value: "42"},
	} {
		t.Run(rule.Kind, func(t *testing.T) {
			store := &guardTestStore{policy: subscribeguard.DefaultPolicy()}
			store.policy.Mode = "enforce"
			store.policy.Rules = []subscribeguard.Rule{rule}
			service := &guardOnceUser{}
			router := NewRouter(config.Config{AppKey: "key"}, WithSubscribeGuard(store), WithUserService(service))
			request := httptest.NewRequest("GET", "/api/v1/client/subscribe?token=single-use", nil)
			request.Header.Set("User-Agent", "curl/8")
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			if recorder.Code != 403 || service.serverCalls != 0 || len(store.events) != 1 || !store.events[0].CrawlerUA || store.events[0].Reason == "crawler_ua" {
				t.Fatalf("crawler switch bypassed explicit blacklist: status=%d events=%+v", recorder.Code, store.events)
			}
		})
	}
}

func TestGuardInsiderMatchPreservesExistingSelection(t *testing.T) {
	rules := []admin.InsiderRuleRecord{
		{ID: 1, Enabled: 1, MatchUserIDRanges: []string{"100-1"}},
		{ID: 2, Enabled: 0, MatchUserIDs: []string{"42"}},
		{ID: 3, Enabled: 1, MatchUserIDs: []string{"'42',43"}, ExtraNodes: []string{"secret-node"}},
	}
	if guardInsiderMatch(rules, 42).(map[string]any)["id"] != int64(3) || guardInsiderMatch(rules, 44).(map[string]any)["id"] != int64(1) || guardInsiderMatch(rules, 101) != nil {
		t.Fatal("insider precedence mismatch")
	}
	raw, _ := json.Marshal(guardInsiderMatch(rules, 42))
	if strings.Contains(string(raw), "secret-node") {
		t.Fatal("node credential leaked")
	}
}

func TestGuardOffIgnoresUserAndRateRules(t *testing.T) {
	store := &guardTestStore{policy: subscribeguard.DefaultPolicy(), denyRate: true}
	store.policy.IPLimit, store.policy.TokenLimit = 1, 1
	store.policy.Rules = []subscribeguard.Rule{{Kind: "user_block", Value: "42"}}
	router := NewRouter(config.Config{AppKey: "key"}, WithSubscribeGuard(store), WithUserService(&guardOnceUser{}))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest("GET", "/api/v1/client/subscribe?token=test", nil))
	if recorder.Code != 200 || len(store.events) != 1 || store.events[0].Reason != "" {
		t.Fatal("off checked rules")
	}
}

func TestGuardCoversNodeDeliveryEntrypoints(t *testing.T) {
	for _, path := range []string{"/api/v1/client/subscribe", "/api/v1/client/app/getConfig", "/api/v1/client/forest/entry-provider", "/api/v1/user/forest/runtime-profile", "/api/v1/user/server/fetch"} {
		t.Run(path, func(t *testing.T) {
			store := &guardTestStore{policy: subscribeguard.DefaultPolicy()}
			store.policy.Mode = "enforce"
			store.policy.Rules = []subscribeguard.Rule{{Kind: "user_block", Value: "42"}}
			service := &guardOnceUser{}
			router := NewRouter(config.Config{AppKey: "key"}, WithSubscribeGuard(store), WithUserService(service), WithSessionService(&fakeSessionService{user: &session.Identity{ID: 42}}))
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest("GET", path+"?token=single-use", nil))
			if recorder.Code != 403 || service.serverCalls != 0 || len(store.events) != 1 || store.events[0].Reason != "user" {
				t.Fatalf("unprotected endpoint: status=%d events=%+v", recorder.Code, store.events)
			}
		})
	}
}

func TestGuardTokenBodyCannotBypassBlock(t *testing.T) {
	for _, test := range []struct{ contentType, body string }{
		{"application/json", `{"token":"blocked-secret"}`},
		{"application/x-www-form-urlencoded", "token=blocked-secret"},
	} {
		store := &guardTestStore{policy: subscribeguard.DefaultPolicy()}
		store.policy.Mode = "enforce"
		store.policy.Rules = []subscribeguard.Rule{{Kind: "token_block", Value: subscribeguard.Fingerprint("key", "blocked-secret")}}
		router := NewRouter(config.Config{AppKey: "key"}, WithSubscribeGuard(store))
		request := httptest.NewRequest("POST", "/api/v1/client/subscribe?token=different", strings.NewReader(test.body))
		request.Header.Set("Content-Type", test.contentType)
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if recorder.Code != 403 || recorder.Header().Get("X-Subscribe-Guard") != "token" {
			t.Fatalf("body token bypassed guard: %d %s", recorder.Code, recorder.Body.String())
		}
	}
}

func TestGuardDegradationAndActualResponseStatus(t *testing.T) {
	for _, kind := range []string{"config_failure", "rate_failure", "backend_failure", "force_off", "rate_limit"} {
		t.Run(kind, func(t *testing.T) {
			store := &guardTestStore{policy: subscribeguard.DefaultPolicy()}
			store.policy.Mode = "enforce"
			store.policy.IPLimit = 10
			service := &guardOnceUser{}
			expected := 200
			switch kind {
			case "config_failure":
				store.err = errors.New("offline")
			case "rate_failure":
				store.rateErr = errors.New("offline")
			case "backend_failure":
				service.subscribeErr = errors.New("backend failed")
				expected = 500
			case "force_off":
				t.Setenv("SUBSCRIBE_GUARD_FORCE_OFF", "1")
				store.policy.BlockEmptyUA = true
			case "rate_limit":
				store.denyRate = true
				expected = 429
			}
			router := NewRouter(config.Config{AppKey: "key"}, WithSubscribeGuard(store), WithUserService(service))
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest("GET", "/api/v1/client/subscribe?token=one", nil))
			if recorder.Code != expected {
				t.Fatalf("status=%d expected %d", recorder.Code, expected)
			}
			if kind == "rate_limit" && recorder.Header().Get("Retry-After") == "" {
				t.Fatal("missing retry hint")
			}
			if len(store.events) > 0 && store.events[0].Status != expected {
				t.Fatalf("wrong event status %+v", store.events)
			}
		})
	}
}

func TestGuardAdminAuthenticationAndSafeSave(t *testing.T) {
	store := &guardTestStore{policy: subscribeguard.DefaultPolicy()}
	unauthorized := NewRouter(config.Config{AdminPath: "localadmin"}, WithSubscribeGuard(store))
	recorder := httptest.NewRecorder()
	unauthorized.ServeHTTP(recorder, httptest.NewRequest("GET", "/api/v1/localadmin/subscribe-access/guard/config", nil))
	if recorder.Code == 200 {
		t.Fatal("anonymous read allowed")
	}
	identity := &fakeSessionService{user: &session.Identity{ID: 7, IsAdmin: 1}}
	router := NewRouter(config.Config{AppKey: "key", AdminPath: "localadmin"}, WithSubscribeGuard(store), WithSessionService(identity))
	policy := subscribeguard.DefaultPolicy()
	policy.Rules = []subscribeguard.Rule{{Kind: "token_block", Token: "raw-secret"}}
	body, _ := json.Marshal(map[string]any{"policy": policy, "auth_data": "admin-session"})
	request := httptest.NewRequest("POST", "/api/v1/localadmin/subscribe-access/guard/config", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != 200 || !identity.lastRequireAdmin || store.saveAdmin != 7 {
		t.Fatalf("invalid save: %d %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "raw-secret") || store.policy.Rules[0].Token != "" {
		t.Fatal("raw token returned or saved")
	}
}

func TestObservePreservesSubscriptionPayload(t *testing.T) {
	for _, flag := range []string{"", "clash", "sing-box", "surge"} {
		t.Run(flag, func(t *testing.T) {
			service := &fakeUserService{resolvedClientUserID: 42, servers: []map[string]any{
				{"type": "trojan", "name": "custom-node", "host": "192.0.2.9", "port": int64(443), "password": "node-password"},
			}}
			cfg := config.Config{AppKey: "key", PublicDir: "../../../public"}
			baseline := NewRouter(cfg, WithUserService(service))
			store := &guardTestStore{policy: subscribeguard.DefaultPolicy()}
			store.policy.Mode = "observe"
			store.policy.BlockEmptyUA = true
			observed := NewRouter(cfg, WithUserService(service), WithSubscribeGuard(store))
			target := "/api/v1/client/subscribe?token=valid&flag=" + flag
			original, guarded := httptest.NewRecorder(), httptest.NewRecorder()
			baseline.ServeHTTP(original, httptest.NewRequest("GET", target, nil))
			observed.ServeHTTP(guarded, httptest.NewRequest("GET", target, nil))
			if original.Code != 200 || guarded.Code != original.Code || guarded.Body.String() != original.Body.String() || guarded.Header().Get("subscription-userinfo") != original.Header().Get("subscription-userinfo") {
				t.Fatalf("payload changed: baseline=%d observed=%d", original.Code, guarded.Code)
			}
		})
	}
}
