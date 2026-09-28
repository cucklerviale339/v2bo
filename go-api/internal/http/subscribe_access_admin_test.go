package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"forest/go-api/internal/config"
	"forest/go-api/internal/session"
)

func TestRouterAdminSubscribeAccessStats(t *testing.T) {
	sessionService := &fakeSessionService{user: &session.Identity{ID: 1, IsAdmin: 1}}
	adminService := &fakeAdminService{}
	router := NewRouter(
		config.Config{AppName: "forest-go", AdminPath: "localadmin"},
		WithSessionService(sessionService),
		WithAdminService(adminService),
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/localadmin/subscribe-access/stats?auth_data=jwt-admin&keyword=demo%40example.com&current=2&page_size=30", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	if !sessionService.lastRequireAdmin {
		t.Fatal("expected admin authentication")
	}
	request := adminService.lastSubscribeAccess
	if request.Keyword != "demo@example.com" || request.Current != 2 || request.PageSize != 30 {
		t.Fatalf("unexpected stats request: %#v", request)
	}
}

func TestRouterAdminSubscribeAccessDetailSearchAndRetention(t *testing.T) {
	sessionService := &fakeSessionService{user: &session.Identity{ID: 1, IsAdmin: 1}}
	adminService := &fakeAdminService{}
	router := NewRouter(
		config.Config{AppName: "forest-go", AdminPath: "localadmin"},
		WithSessionService(sessionService),
		WithAdminService(adminService),
	)

	tests := []struct {
		name   string
		method string
		path   string
		body   []byte
	}{
		{name: "detail", method: http.MethodGet, path: "/api/v1/localadmin/subscribe-access/user-detail?auth_data=jwt-admin&id=9"},
		{name: "UA search", method: http.MethodGet, path: "/api/v1/localadmin/subscribe-access/ua-search?auth_data=jwt-admin&keyword=Clash&current=2&page_size=30"},
		{name: "retention", method: http.MethodPost, path: "/api/v1/localadmin/subscribe-access/retention", body: []byte(`{"auth_data":"jwt-admin","days":30}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(test.method, test.path, bytes.NewReader(test.body))
			if len(test.body) > 0 {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d with body %s", rec.Code, rec.Body.String())
			}
		})
	}
	if adminService.lastSubscribeDetailID != 9 {
		t.Fatalf("unexpected detail user ID: %d", adminService.lastSubscribeDetailID)
	}
	if adminService.lastSubscribeUAKeyword != "Clash" || adminService.lastSubscribeUACurrent != 2 || adminService.lastSubscribeUAPageSize != 30 {
		t.Fatalf("unexpected UA search: %#v", adminService)
	}
	if adminService.lastSubscribeKeepDays != 30 {
		t.Fatalf("unexpected retention days: %d", adminService.lastSubscribeKeepDays)
	}
}

func TestRouterAdminSubscribeAccessStatsRejectsInvalidPageSize(t *testing.T) {
	sessionService := &fakeSessionService{user: &session.Identity{ID: 1, IsAdmin: 1}}
	router := NewRouter(
		config.Config{AppName: "forest-go", AdminPath: "localadmin"},
		WithSessionService(sessionService),
		WithAdminService(&fakeAdminService{}),
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/localadmin/subscribe-access/stats?auth_data=jwt-admin&page_size=101", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestRouterAdminDailyLowTrafficUsers(t *testing.T) {
	sessionService := &fakeSessionService{user: &session.Identity{ID: 1, IsAdmin: 1}}
	adminService := &fakeAdminService{}
	router := NewRouter(
		config.Config{AppName: "forest-go", AdminPath: "localadmin"},
		WithSessionService(sessionService),
		WithAdminService(adminService),
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/localadmin/subscribe-access/low-traffic?auth_data=jwt-admin&current=2&page_size=30&threshold_kb=350", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	if !sessionService.lastRequireAdmin {
		t.Fatal("expected admin authentication")
	}
	if adminService.lastLowTrafficCurrent != 2 || adminService.lastLowTrafficPageSize != 30 || adminService.lastLowTrafficThreshold != 350*1024 {
		t.Fatalf("unexpected request: current=%d page_size=%d threshold=%d", adminService.lastLowTrafficCurrent, adminService.lastLowTrafficPageSize, adminService.lastLowTrafficThreshold)
	}
}

func TestRouterAdminConsecutiveLowTrafficUsers(t *testing.T) {
	sessionService := &fakeSessionService{user: &session.Identity{ID: 1, IsAdmin: 1}}
	adminService := &fakeAdminService{}
	router := NewRouter(
		config.Config{AppName: "forest-go", AdminPath: "localadmin"},
		WithSessionService(sessionService),
		WithAdminService(adminService),
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/localadmin/subscribe-access/consecutive-low-traffic?auth_data=jwt-admin&current=2&page_size=30&threshold_kb=350&days=7", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	if adminService.lastConsecutiveCurrent != 2 || adminService.lastConsecutivePageSize != 30 || adminService.lastConsecutiveThreshold != 350*1024 || adminService.lastConsecutiveDays != 7 {
		t.Fatalf("unexpected consecutive request: current=%d page_size=%d threshold=%d days=%d", adminService.lastConsecutiveCurrent, adminService.lastConsecutivePageSize, adminService.lastConsecutiveThreshold, adminService.lastConsecutiveDays)
	}
}

func TestRouterAdminConsecutiveLowTrafficUsersRejectsInvalidDays(t *testing.T) {
	sessionService := &fakeSessionService{user: &session.Identity{ID: 1, IsAdmin: 1}}
	router := NewRouter(
		config.Config{AppName: "forest-go", AdminPath: "localadmin"},
		WithSessionService(sessionService),
		WithAdminService(&fakeAdminService{}),
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/localadmin/subscribe-access/consecutive-low-traffic?auth_data=jwt-admin&days=366", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestRouterAdminDailyLowTrafficUsersRejectsInvalidThreshold(t *testing.T) {
	sessionService := &fakeSessionService{user: &session.Identity{ID: 1, IsAdmin: 1}}
	router := NewRouter(
		config.Config{AppName: "forest-go", AdminPath: "localadmin"},
		WithSessionService(sessionService),
		WithAdminService(&fakeAdminService{}),
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/localadmin/subscribe-access/low-traffic?auth_data=jwt-admin&threshold_kb=0", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestSubscribeAccessClientIP(t *testing.T) {
	tests := []struct {
		name       string
		headerName string
		header     string
		remoteAddr string
		want       string
	}{
		{name: "untrusted cloudflare header", headerName: "CF-Connecting-IP", header: "203.0.113.7", remoteAddr: "10.0.0.2:3000", want: "10.0.0.2"},
		{name: "untrusted forwarded header", headerName: "X-Forwarded-For", header: "198.51.100.4, 10.0.0.2", remoteAddr: "10.0.0.2:3000", want: "10.0.0.2"},
		{name: "local forwarded", headerName: "X-Forwarded-For", header: "192.0.2.1, 198.51.100.4", remoteAddr: "127.0.0.1:3000", want: "198.51.100.4"},
		{name: "local real IP", headerName: "X-Real-IP", header: "198.51.100.4", remoteAddr: "127.0.0.1:3000", want: "198.51.100.4"},
		{name: "remote address", remoteAddr: "192.0.2.8:3000", want: "192.0.2.8"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = test.remoteAddr
			if test.headerName != "" {
				req.Header.Set(test.headerName, test.header)
			}
			if got := subscribeAccessClientIP(req); got != test.want {
				t.Fatalf("expected %q, got %q", test.want, got)
			}
		})
	}
}
