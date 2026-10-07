package httpapi

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"forest/go-api/internal/config"
	"forest/go-api/internal/session"
	"forest/go-api/internal/subscribeguard"
)

type monitorTestStore struct {
	riskTestStore
	writes   int
	adminID  int64
	conflict bool
}

func (store *monitorTestStore) MonitoringStatus(context.Context) (subscribeguard.MonitorStatus, error) {
	return subscribeguard.MonitorStatus{Ready: true}, nil
}
func (store *monitorTestStore) SetIPLookup(_ context.Context, _ bool, _ int64, adminID int64) error {
	store.writes++
	store.adminID = adminID
	if store.conflict {
		return subscribeguard.ErrConflict
	}
	return nil
}
func (store *monitorTestStore) RetryIPLookups(context.Context) (int64, error) {
	store.writes++
	return 1, nil
}
func (store *monitorTestStore) RiskHistory(context.Context, subscribeguard.RiskHistoryFilter) (subscribeguard.RiskHistoryResult, error) {
	return subscribeguard.RiskHistoryResult{Data: []subscribeguard.RiskHistoryEntry{}}, nil
}
func (store *monitorTestStore) ReviewRisk(_ context.Context, _, _, adminID int64, _, _ string) error {
	store.writes++
	store.adminID = adminID
	return nil
}

func TestMonitoringAuthorizationValidationAndConflict(t *testing.T) {
	store := &monitorTestStore{}
	const prefix = "/api/v1/localadmin/subscribe-access/guard/"
	anonymous := NewRouter(config.Config{AdminPath: "localadmin"}, WithSubscribeGuard(store), WithAdminService(&fakeAdminService{}))
	for _, action := range []string{"monitor-status", "risk-history", "monitor-config", "monitor-retry", "risk-review"} {
		method := "GET"
		if action == "monitor-config" || action == "monitor-retry" || action == "risk-review" {
			method = "POST"
		}
		recorder := httptest.NewRecorder()
		anonymous.ServeHTTP(recorder, httptest.NewRequest(method, prefix+action, strings.NewReader(`{}`)))
		if recorder.Code == 200 {
			t.Fatal("anonymous access allowed", action)
		}
	}
	identity := &fakeSessionService{user: &session.Identity{ID: 7, IsAdmin: 1}}
	router := NewRouter(config.Config{AdminPath: "localadmin"}, WithSubscribeGuard(store), WithAdminService(&fakeAdminService{}), WithSessionService(identity))
	for _, test := range []struct {
		method, action, body string
		status               int
	}{
		{"GET", "monitor-config", "", 405},
		{"GET", "monitor-status", "", 200},
		{"GET", "risk-history?status=suppressed", "", 200},
		{"GET", "risk-history?status=invalid", "", 400},
		{"GET", "risk-history?current=0", "", 400},
		{"POST", "monitor-config", `{"enabled":true}`, 400},
		{"POST", "risk-review", `{"id":1,"revision":0,"status":"handled","note":""}`, 400},
		{"POST", "risk-review", `{"id":1,"revision":0,"status":"ban","note":"test"}`, 400},
		{"POST", "monitor-config", `{"revision":0,"enabled":false}`, 200},
		{"POST", "risk-review", `{"id":1,"revision":0,"status":"handled","note":"test"}`, 200},
	} {
		separator := "?"
		if strings.Contains(test.action, "?") {
			separator = "&"
		}
		request := httptest.NewRequest(test.method, prefix+test.action+separator+"auth_data=admin", strings.NewReader(test.body))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if recorder.Code != test.status {
			t.Fatalf("%s: %d %s", test.action, recorder.Code, recorder.Body.String())
		}
	}
	if store.writes != 2 || store.adminID != 7 || !identity.lastRequireAdmin {
		t.Fatal("invalid operation reached store", store.writes)
	}
	store.conflict = true
	request := httptest.NewRequest("POST", prefix+"monitor-config?auth_data=admin", strings.NewReader(`{"revision":0,"enabled":true}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != 409 {
		t.Fatal("stale config not rejected", recorder.Code)
	}
}
