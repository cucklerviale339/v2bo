package httpapi

import (
	"context"
	"strings"
	"testing"

	"forest/go-api/internal/admin"
	"forest/go-api/internal/config"
	"forest/go-api/internal/session"
)

type fakeDispatchHistory struct {
	*fakeDNSAdminService
	request admin.DispatchHistoryRequest
	calls   int
}

func (f *fakeDispatchHistory) ListDispatchHistory(_ context.Context, r admin.DispatchHistoryRequest) (admin.DispatchHistoryResult, error) {
	f.request = r
	f.calls++
	return admin.DispatchHistoryResult{Data: []admin.DispatchHistoryRecord{}, Page: r.Page, PageSize: 50}, nil
}

func TestDispatchHistoryRouteIsAdminOnlyAndDoesNotStartOrClearChecks(t *testing.T) {
	f := &fakeDispatchHistory{fakeDNSAdminService: &fakeDNSAdminService{}}
	path := "/api/v1/control/dns-failover/dispatch-history"
	auth := &fakeSessionService{authErr: session.ErrUnauthorized}
	router := NewRouter(config.Config{AdminPath: "control"}, WithSessionService(auth), WithAdminService(f))
	if r := dnsFailoverRequest(router, "GET", path, ""); r.Code != 403 || !auth.lastRequireAdmin || f.calls != 0 {
		t.Fatal("unauthenticated history access")
	}
	router = NewRouter(config.Config{AdminPath: "control"}, WithSessionService(&fakeSessionService{user: &session.Identity{ID: 1, IsAdmin: 1}}), WithAdminService(f))
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		if r := dnsFailoverRequest(router, method, path, ""); r.Code != 405 || r.Header().Get("Allow") != "GET" {
			t.Fatal(method, r.Code)
		}
	}
	for _, q := range []string{"?page=0", "?page=no", "?page=1&page=2", "?probe_id=-1", "?from=no", "?success=1"} {
		if r := dnsFailoverRequest(router, "GET", path+q, ""); r.Code != 400 {
			t.Fatal(q, r.Code)
		}
	}
	if f.calls != 0 {
		t.Fatal("invalid request reached service")
	}
	r := dnsFailoverRequest(router, "GET", path+"?page=2&kind=event&source=pool&host=192.0.2.1&success=false&probe_id=7&from=10&to=20", "")
	if r.Code != 200 || !strings.Contains(r.Header().Get("Cache-Control"), "no-store") || f.request.Page != 2 || f.request.Source != "pool" || f.request.Success == nil || *f.request.Success || f.request.ProbeID != 7 || f.request.From != 10 || f.request.To != 20 {
		t.Fatalf("history query: %d %#v", r.Code, f.request)
	}
}
