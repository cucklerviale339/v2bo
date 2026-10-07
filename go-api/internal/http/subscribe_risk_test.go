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

type riskTestStore struct {
	guardTestStore
	filter subscribeguard.RiskFilter
	token  string
	userID int64
}

func (store *riskTestStore) Risks(_ context.Context, filter subscribeguard.RiskFilter) (subscribeguard.RiskResult, error) {
	store.filter = filter
	return subscribeguard.RiskResult{Data: []subscribeguard.RiskProfile{}}, nil
}

func (store *riskTestStore) RiskEvents(_ context.Context, token string, userID int64) ([]subscribeguard.Event, error) {
	store.token, store.userID = token, userID
	return []subscribeguard.Event{}, nil
}

func TestRiskEndpointsRequireAdminAndValidateQueries(t *testing.T) {
	store := &riskTestStore{}
	const path = "/api/v1/localadmin/subscribe-access/guard/"
	anonymous := NewRouter(config.Config{AdminPath: "localadmin"}, WithSubscribeGuard(store), WithAdminService(&fakeAdminService{}))
	for _, action := range []string{"risk", "risk-events?id=42"} {
		recorder := httptest.NewRecorder()
		anonymous.ServeHTTP(recorder, httptest.NewRequest("GET", path+action, nil))
		if recorder.Code == 200 {
			t.Fatal("anonymous risk access allowed")
		}
	}
	identity := &fakeSessionService{user: &session.Identity{ID: 7, IsAdmin: 1}}
	router := NewRouter(config.Config{AdminPath: "localadmin"}, WithSubscribeGuard(store), WithAdminService(&fakeAdminService{}), WithSessionService(identity))
	for _, query := range []string{"current=0", "min_score=bad", "min_score=101", "page_size=101", "current=100001", "page_size=99999999999999999999999"} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest("GET", path+"risk?auth_data=admin&"+query, nil))
		if recorder.Code != 400 {
			t.Fatalf("query %s: %d %s", query, recorder.Code, recorder.Body.String())
		}
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest("GET", path+"risk?auth_data=admin&keyword=42&current=2&min_score=40", nil))
	if recorder.Code != 200 || !identity.lastRequireAdmin || store.filter.Current != 2 || store.filter.MinScore != 40 || store.filter.Keyword != "42" {
		t.Fatalf("incorrect risk query: %d %+v", recorder.Code, store.filter)
	}
	for _, query := range []string{"", "id=-1", "token_hash=invalid"} {
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest("GET", path+"risk-events?auth_data=admin&"+query, nil))
		if recorder.Code != 400 {
			t.Fatalf("bad identity %s: %d", query, recorder.Code)
		}
	}
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest("GET", path+"risk-events?auth_data=admin&token_hash="+strings.Repeat("A", 64), nil))
	if recorder.Code != 200 || store.token != strings.Repeat("a", 64) {
		t.Fatal("fingerprint details failed", recorder.Body.String())
	}
}
