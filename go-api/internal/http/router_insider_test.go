package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"forest/go-api/internal/admin"
	"forest/go-api/internal/config"
	"forest/go-api/internal/session"
)

func TestRouterAdminInsiderSaveRejectsOversizedBody(t *testing.T) {
	router := NewRouter(
		config.Config{AppName: "forest-go", AdminPath: "localadmin"},
		WithSessionService(&fakeSessionService{user: &session.Identity{ID: 1, IsAdmin: 1}}),
		WithAdminService(&fakeAdminService{}),
	)
	body := `{"name":"rule","match_user_ids":["1"],"host":"` + strings.Repeat("a", (2<<20)+1) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/localadmin/server/insider/save?auth_data=admin", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "读取请求体失败") {
		t.Fatalf("expected body limit error, got %s", rec.Body.String())
	}
}

func TestRouterAdminInsiderSaveReturnsBadRequestForValidationError(t *testing.T) {
	router := NewRouter(
		config.Config{AppName: "forest-go", AdminPath: "localadmin"},
		WithSessionService(&fakeSessionService{user: &session.Identity{ID: 1, IsAdmin: 1}}),
		WithAdminService(&fakeAdminService{err: fmt.Errorf("%w: 规则名称不能为空", admin.ErrInvalidInsiderRule)}),
	)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/localadmin/server/insider/save?auth_data=admin", strings.NewReader(`{"name":""}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "规则名称不能为空") {
		t.Fatalf("expected validation 400, got %d: %s", rec.Code, rec.Body.String())
	}
}
