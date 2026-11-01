package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"forest/go-api/internal/admin"
	"forest/go-api/internal/config"
	"forest/go-api/internal/session"
)

type fakeDispatchChecks struct {
	*fakeDNSAdminService
	starts int
	saves  int
}

func (f *fakeDispatchChecks) ListDispatchPool(context.Context) ([]admin.DispatchPoolItem, error) {
	return []admin.DispatchPoolItem{}, nil
}
func (f *fakeDispatchChecks) SaveDispatchPool(context.Context, []admin.DispatchPoolSave) ([]int64, error) {
	f.saves++
	return []int64{1}, nil
}
func (f *fakeDispatchChecks) RefreshDispatchPool(context.Context, []int64) error { return nil }
func (f *fakeDispatchChecks) DeleteDispatchPool(context.Context, []int64) (int64, error) {
	return 1, nil
}
func (f *fakeDispatchChecks) DeleteFaultyDispatchPool(context.Context, []int64) (admin.DispatchPoolDeleteResult, error) {
	return admin.DispatchPoolDeleteResult{Deleted: 1}, nil
}
func (f *fakeDispatchChecks) StartDispatchRun(context.Context, admin.DispatchRunRequest) (int64, error) {
	f.starts++
	return 42, nil
}
func (f *fakeDispatchChecks) ListDispatchRuns(context.Context, int) ([]admin.DispatchCheckRun, int64, error) {
	return []admin.DispatchCheckRun{{ID: 42, Expected: 2}}, 1, nil
}
func (f *fakeDispatchChecks) DispatchRunResults(context.Context, int64, int) ([]admin.DispatchCheckResult, int64, error) {
	return []admin.DispatchCheckResult{}, 0, nil
}
func (f *fakeDispatchChecks) ClearDispatchRuns(context.Context) (int64, error) { return 1, nil }

func TestDispatchCheckRoutesAuthenticateBoundJSONAndPaginate(t *testing.T) {
	f := &fakeDispatchChecks{fakeDNSAdminService: &fakeDNSAdminService{}}
	paths := []string{"dispatch-pool", "dispatch-pool/refresh", "dispatch-pool/delete", "dispatch-runs", "dispatch-runs/42"}
	for _, path := range paths {
		auth := &fakeSessionService{authErr: session.ErrUnauthorized}
		router := NewRouter(config.Config{AdminPath: "control"}, WithSessionService(auth), WithAdminService(f))
		if r := dnsFailoverRequest(router, http.MethodGet, "/api/v1/control/dns-failover/"+path, ""); r.Code != 403 || !auth.lastRequireAdmin {
			t.Fatalf("%s: %d", path, r.Code)
		}
	}
	router := NewRouter(config.Config{AdminPath: "control"}, WithSessionService(&fakeSessionService{user: &session.Identity{ID: 1, IsAdmin: 1}}), WithAdminService(f))
	prefix := "/api/v1/control/dns-failover/"
	for _, c := range []struct{ method, path, body string }{{"GET", "dispatch-pool", ""}, {"POST", "dispatch-pool", `{"items":[]}`}, {"POST", "dispatch-pool/refresh", `{"ids":[1]}`}, {"POST", "dispatch-pool/delete", `{"ids":[1]}`}, {"GET", "dispatch-runs?page=2", ""}, {"GET", "dispatch-runs/42?page=2", ""}, {"DELETE", "dispatch-runs", ""}} {
		r := dnsFailoverRequest(router, c.method, prefix+c.path, c.body)
		if r.Code != 200 || !strings.Contains(r.Header().Get("Cache-Control"), "no-store") {
			t.Fatal(c, r.Code, r.Body.String())
		}
	}
	for _, body := range []string{`{"hosts":[],"unknown":true}`, `{} {}`, `{"hosts":["` + strings.Repeat("x", maxDNSFailoverJSONBody) + `"]}`} {
		if r := dnsFailoverRequest(router, "POST", prefix+"dispatch-pool/delete-faulty", body); r.Code < 400 {
			t.Fatal("bad body accepted")
		}
	}
	for _, path := range []string{"dispatch-runs?page=0", "dispatch-runs?page=hello", "dispatch-runs/not-a-number"} {
		if r := dnsFailoverRequest(router, "GET", prefix+path, ""); r.Code != 400 {
			t.Fatal(path, r.Code)
		}
	}
	if f.starts != 0 || f.saves != 1 {
		t.Fatal("invalid requests reached service", f.starts, f.saves)
	}
}

type fakeCheckProbe struct {
	*fakeDispatchProbe
	checks []admin.DNSProbeResultsRequest
}

func (f *fakeCheckProbe) ListDispatchCheckTasks(context.Context, int64) ([]admin.DNSProbeTask, error) {
	return []admin.DNSProbeTask{{TargetID: -(1 << 60) - 7, RunID: 1, TargetVersion: 1}}, nil
}
func (f *fakeCheckProbe) ReportDispatchCheckResults(_ context.Context, _ int64, r admin.DNSProbeResultsRequest) (admin.DNSProbeReportResult, error) {
	f.checks = append(f.checks, r)
	return admin.DNSProbeReportResult{Accepted: len(r.Results)}, nil
}
func TestProbeTransportSeparatesThreeTaskNamespaces(t *testing.T) {
	f := &fakeCheckProbe{fakeDispatchProbe: &fakeDispatchProbe{fakeDNSProbeService: &fakeDNSProbeService{tasks: []admin.DNSProbeTask{{TargetID: 7}}, reportResult: admin.DNSProbeReportResult{Accepted: 1}}}}
	router := NewRouter(config.Config{}, WithDNSProbeService(f))
	request := func(method, path, body string) string { return checkProbeRequest(t, router, method, path, body) }
	tasks := request("GET", "/api/v1/probe/monitor-tasks", "")
	if !strings.Contains(tasks, "-1152921504606846983") || strings.Contains(tasks, `"target_id":7`) {
		t.Fatal(tasks)
	}
	body := request("POST", "/api/v1/probe/monitor-results", `{"results":[{"target_id":-7,"result_id":"-7-1","success":true},{"target_id":-1152921504606846983,"result_id":"check-1","success":true}]}`)
	if len(f.checks) != 1 || len(f.dispatchReports) != 1 || len(f.reports) != 0 || !strings.Contains(body, `"accepted":2`) {
		t.Fatal(body)
	}
	request("POST", "/api/v1/probe/results", `{"results":[{"target_id":7,"result_id":"dns-1","success":true}]}`)
	if len(f.reports) != 1 {
		t.Fatal("legacy result missing")
	}
}

func checkProbeRequest(t *testing.T, router http.Handler, method, path, body string) string {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer good-secret")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}
