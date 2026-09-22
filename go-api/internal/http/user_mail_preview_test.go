package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"forest/go-api/internal/admin"
	"forest/go-api/internal/config"
	"forest/go-api/internal/session"
)

type fakeMailPreviewService struct {
	*fakeAdminService
	request admin.UserMailRequest
	called  bool
}

func (service *fakeMailPreviewService) PreviewUserMail(_ context.Context, req admin.UserMailRequest) (admin.UserMailPreview, error) {
	service.request = req
	service.called = true
	return admin.UserMailPreview{Total: 10, Excluded: 3, Unavailable: 1, Eligible: 6}, service.err
}

func TestRouterMailPreviewUsesSendScope(t *testing.T) {
	for _, staff := range []bool{false, true} {
		sessions := &fakeSessionService{user: &session.Identity{ID: 1, IsAdmin: 1, IsStaff: 1}}
		service := &fakeMailPreviewService{fakeAdminService: &fakeAdminService{}}
		router := NewRouter(config.Config{AdminPath: "localadmin"}, WithSessionService(sessions), WithAdminService(service))
		prefix := "/api/v1/localadmin"
		filters := []admin.UserFilter{{Key: "banned", Condition: "=", Value: "0"}}
		if staff {
			prefix = "/api/v1/staff"
			filters = append(filters, admin.UserFilter{Key: "is_admin", Condition: "=", Value: "0"}, admin.UserFilter{Key: "is_staff", Condition: "=", Value: "0"})
		}
		req := httptest.NewRequest(http.MethodPost, prefix+"/user/mailPreview", strings.NewReader("auth_data=jwt&filter[0][key]=banned&filter[0][condition]==&filter[0][value]=0"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !service.called || sessions.lastRequireAdmin == staff || !reflect.DeepEqual(service.request.Filters, filters) {
			t.Fatalf("scope mismatch staff=%v status=%d filters=%v", staff, rec.Code, service.request.Filters)
		}
		var result struct {
			Data admin.UserMailPreview `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil || result.Data != (admin.UserMailPreview{Total: 10, Excluded: 3, Unavailable: 1, Eligible: 6}) {
			t.Fatalf("unexpected response: %s", rec.Body.String())
		}
	}
}

func TestRouterMailPreviewRejectsUnauthorizedAndInvalidRequests(t *testing.T) {
	for _, test := range []struct {
		name, prefix, method string
		identity             *session.Identity
		authErr              error
		serviceErr           error
		status               int
		called               bool
	}{
		{name: "unauthenticated", prefix: "localadmin", method: http.MethodPost, authErr: session.ErrUnauthorized, status: http.StatusForbidden},
		{name: "non staff", prefix: "staff", method: http.MethodPost, identity: &session.Identity{ID: 1}, status: http.StatusForbidden},
		{name: "admin GET", prefix: "localadmin", method: http.MethodGet, identity: &session.Identity{ID: 1, IsAdmin: 1}, status: http.StatusMethodNotAllowed},
		{name: "staff GET", prefix: "staff", method: http.MethodGet, identity: &session.Identity{ID: 1, IsStaff: 1}, status: http.StatusMethodNotAllowed},
		{name: "list failure", prefix: "localadmin", method: http.MethodPost, identity: &session.Identity{ID: 1, IsAdmin: 1}, serviceErr: errors.New("名单读取失败"), status: http.StatusInternalServerError, called: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &fakeMailPreviewService{fakeAdminService: &fakeAdminService{err: test.serviceErr}}
			sessions := &fakeSessionService{user: test.identity, authErr: test.authErr}
			router := NewRouter(config.Config{AdminPath: "localadmin"}, WithSessionService(sessions), WithAdminService(service))
			req := httptest.NewRequest(test.method, "/api/v1/"+test.prefix+"/user/mailPreview", strings.NewReader("auth_data=jwt"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != test.status || service.called != test.called {
				t.Fatalf("status=%d called=%v body=%s", rec.Code, service.called, rec.Body.String())
			}
		})
	}
}

func TestRouterMailPreviewUnavailable(t *testing.T) {
	router := NewRouter(config.Config{AdminPath: "localadmin"}, WithSessionService(&fakeSessionService{user: &session.Identity{ID: 1, IsAdmin: 1}}), WithAdminService(&fakeAdminService{}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/localadmin/user/mailPreview", strings.NewReader("auth_data=jwt"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected unavailable preview, got %d", rec.Code)
	}
}

func TestRouterMailJSONFiltersApplyToPreviewAndSend(t *testing.T) {
	for _, prefix := range []string{"localadmin", "staff"} {
		for _, action := range []string{"mailPreview", "sendMail"} {
			service := &fakeMailPreviewService{fakeAdminService: &fakeAdminService{}}
			router := NewRouter(config.Config{AdminPath: "localadmin"}, WithSessionService(&fakeSessionService{user: &session.Identity{ID: 1, IsAdmin: 1, IsStaff: 1}}), WithAdminService(service))
			req := httptest.NewRequest(http.MethodPost, "/api/v1/"+prefix+"/user/"+action, strings.NewReader(`{"auth_data":"jwt","subject":"Notice","content":"Hello","filter":[{"key":"id","condition":"=","value":9223372036854775807}]}`))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			filters := service.request.Filters
			if action == "sendMail" {
				filters = service.lastUserMail.Filters
			}
			if rec.Code != http.StatusOK || len(filters) == 0 || filters[0] != (admin.UserFilter{Key: "id", Condition: "=", Value: "9223372036854775807"}) {
				t.Fatalf("JSON filter ignored: %s %s status=%d filters=%v", prefix, action, rec.Code, filters)
			}
			if prefix == "staff" && len(filters) != 3 {
				t.Fatalf("staff scope missing: %v", filters)
			}
		}
	}
}

func TestRouterMailRejectsMalformedFilters(t *testing.T) {
	for _, body := range []string{
		`{"filter":"invalid"}`,
		`{"filter":{}}`,
		`{"filter":[{"key":"id","condition":"="}]}`,
		`{"filter":[{"key":"id","condition":"=","value":null}]}`,
		`{"filter":[{"key":"id","condition":"=","value":true}]}`,
		`{"filter":[{"key":"id","value":1}]}`,
		`{"filter":[{"key":"","condition":"=","value":1}]}`,
		`{"filter":[],"filter[0][key]":"id"}`,
		`filter[0][key]=id&filter[0][condition]==`,
		`filter[wrong][key]=id`,
	} {
		for _, prefix := range []string{"localadmin", "staff"} {
			for _, action := range []string{"mailPreview", "sendMail"} {
				service := &fakeMailPreviewService{fakeAdminService: &fakeAdminService{}}
				router := NewRouter(config.Config{AdminPath: "localadmin"}, WithSessionService(&fakeSessionService{user: &session.Identity{ID: 1, IsAdmin: 1, IsStaff: 1}}), WithAdminService(service))
				req := httptest.NewRequest(http.MethodPost, "/api/v1/"+prefix+"/user/"+action, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				if !strings.HasPrefix(body, "{") {
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				if rec.Code != http.StatusBadRequest || service.called || service.lastUserMail.Filters != nil {
					t.Fatalf("malformed filter accepted: %s %s %s status=%d", prefix, action, body, rec.Code)
				}
			}
		}
	}
}
