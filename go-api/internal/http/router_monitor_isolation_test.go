package httpapi

import (
	"context"
	"errors"
	"forest/go-api/internal/admin"
	"forest/go-api/internal/config"
	"net/http/httptest"
	"strings"
	"testing"
)

type brokenAuxiliaryProbe struct{ *fakeDNSProbeService }

func (f *brokenAuxiliaryProbe) ListDispatchProbeTasks(context.Context, int64) ([]admin.DNSProbeTask, error) {
	return nil, errors.New("catalog unavailable")
}
func (f *brokenAuxiliaryProbe) ReportDispatchProbeResults(context.Context, int64, admin.DNSProbeResultsRequest) (admin.DNSProbeReportResult, error) {
	return admin.DNSProbeReportResult{}, errors.New("monitor write unavailable")
}
func TestAuxiliaryFailuresNeverBlockLegacyTaskAndReport(t *testing.T) {
	f := &brokenAuxiliaryProbe{&fakeDNSProbeService{tasks: []admin.DNSProbeTask{{TargetID: 7}}, reportResult: admin.DNSProbeReportResult{Accepted: 1}}}
	router := NewRouter(config.Config{}, WithDNSProbeService(f))
	call := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer good-secret")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	if w := call("GET", "/api/v1/probe/tasks", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"target_id":7`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("GET", "/api/v1/probe/monitor-tasks", ""); w.Code != 500 {
		t.Fatal(w.Code)
	}
	mixed := `{"results":[{"target_id":7,"result_id":"dns-1","success":true},{"target_id":-7,"result_id":"-7-1","target_version":1,"run_id":1,"success":true}]}`
	if w := call("POST", "/api/v1/probe/results", mixed); w.Code != 200 || len(f.reports) != 1 || len(f.reports[0].Results) != 1 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("POST", "/api/v1/probe/monitor-results", mixed); w.Code != 400 || len(f.reports) != 1 {
		t.Fatal("negative endpoint wrote a legacy result", w.Code)
	}
	if w := call("POST", "/api/v1/probe/monitor-results", `{"results":[{"target_id":-7,"result_id":"-7-1","target_version":1,"run_id":1,"success":true}]}`); w.Code != 500 {
		t.Fatal(w.Code)
	}
	if w := call("POST", "/api/v1/probe/results", `{"results":[{"target_id":7,"result_id":"dns-2","success":true}]}`); w.Code != 200 || len(f.reports) != 2 {
		t.Fatal(w.Code)
	}
}

type oversizedAuxiliaryProbe struct {
	*fakeDispatchProbe
	count int
}

func (f *oversizedAuxiliaryProbe) ListDispatchProbeTasks(context.Context, int64) ([]admin.DNSProbeTask, error) {
	tasks := make([]admin.DNSProbeTask, f.count)
	for i := range tasks {
		tasks[i] = admin.DNSProbeTask{TargetID: -int64(i + 1), CheckHost: strings.Repeat("a", 250), CheckPort: 65535, TargetVersion: 9223372036854775807, RunID: 9223372036854775807}
	}
	return tasks, nil
}
func TestAuxiliaryTaskBudgetIsExplicitAndBelowDecoderLimit(t *testing.T) {
	f := &oversizedAuxiliaryProbe{fakeDispatchProbe: &fakeDispatchProbe{fakeDNSProbeService: &fakeDNSProbeService{tasks: []admin.DNSProbeTask{{TargetID: 7}}}}, count: 1000}
	router := NewRouter(config.Config{}, WithDNSProbeService(f))
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer good-secret")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	if w := get("/api/v1/probe/monitor-tasks"); w.Code != 200 || w.Body.Len() >= 768<<10 {
		t.Fatal(w.Code, w.Body.Len())
	}
	f.count = 1001
	if w := get("/api/v1/probe/monitor-tasks"); w.Code != 409 {
		t.Fatal(w.Code)
	}
	if w := get("/api/v1/probe/tasks"); w.Code != 200 {
		t.Fatal("capacity affected DNS", w.Code)
	}
}
