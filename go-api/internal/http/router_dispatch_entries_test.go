package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"forest/go-api/internal/admin"
	"forest/go-api/internal/config"
	"forest/go-api/internal/session"
	usersvc "forest/go-api/internal/user"
)

type fakeDispatchAdmin struct {
	*fakeDNSAdminService
	saves   []admin.DispatchMonitorSaveRequest
	deleted [][]string
}

func (f *fakeDispatchAdmin) ListDispatchMonitors(context.Context) ([]admin.DispatchMonitor, error) {
	return []admin.DispatchMonitor{{DispatchEntry: usersvc.DispatchEntry{Host: "entry.example", UserIDs: []string{"42"}, UserIDRanges: []string{"100-200"}}, CheckPort: 1443}}, nil
}
func (f *fakeDispatchAdmin) SaveDispatchMonitor(_ context.Context, r admin.DispatchMonitorSaveRequest) error {
	f.saves = append(f.saves, r)
	return nil
}

func (f *fakeDispatchAdmin) ListDispatchMonitorsIncludingDeleted(ctx context.Context) ([]admin.DispatchMonitor, error) {
	rows, err := f.ListDispatchMonitors(ctx)
	return append(rows, admin.DispatchMonitor{DispatchEntry: usersvc.DispatchEntry{Host: "deleted.example"}, Deleted: true}), err
}

func (f *fakeDispatchAdmin) DeleteDispatchMonitors(_ context.Context, hosts []string) error {
	if len(hosts) == 0 {
		return admin.ErrDNSProbeInvalidRequest
	}
	f.deleted = append(f.deleted, hosts)
	return nil
}

func TestDispatchDeleteAndDeletedViewRoutes(t *testing.T) {
	f := &fakeDispatchAdmin{fakeDNSAdminService: &fakeDNSAdminService{}}
	path := "/api/v1/control/dns-failover/dispatch-entries"
	for _, identity := range []*session.Identity{nil, {ID: 1}, {ID: 2, IsStaff: 1}, {ID: 3, IsAdmin: 1}} {
		auth := &fakeSessionService{user: identity}
		if identity == nil || identity.IsAdmin == 0 {
			auth.authErr = session.ErrUnauthorized
		}
		router := NewRouter(config.Config{AdminPath: "control"}, WithSessionService(auth), WithAdminService(f))
		if identity == nil || identity.IsAdmin == 0 {
			for _, method := range []string{http.MethodPost, http.MethodGet} {
				target := path + "/delete"
				if method == http.MethodGet {
					target = path + "?include_deleted=true"
				}
				if rec := dnsFailoverRequest(router, method, target, `{"hosts":["entry.example"]}`); rec.Code != http.StatusForbidden {
					t.Fatalf("unauthorized: %d %s", rec.Code, rec.Body.String())
				}
			}
			continue
		}
		for _, query := range []string{"", "?include_deleted=false", "?include_deleted=true"} {
			rec := dnsFailoverRequest(router, http.MethodGet, path+query, "")
			if rec.Code != 200 || strings.Contains(rec.Body.String(), "deleted.example") != (query == "?include_deleted=true") {
				t.Fatalf("view: %d %s", rec.Code, rec.Body.String())
			}
		}
		if rec := dnsFailoverRequest(router, http.MethodGet, path+"?include_deleted=bad", ""); rec.Code != 400 {
			t.Fatal(rec.Code)
		}
		for _, body := range []string{`{}`, `{"hosts":[]}`, `{"hosts":["entry.example"],"unexpected":true}`, `{"hosts":["entry.example"]}{}`, `{"hosts":"entry.example"}`} {
			if rec := dnsFailoverRequest(router, http.MethodPost, path+"/delete", body); rec.Code != 400 {
				t.Fatalf("bad payload: %d %s", rec.Code, rec.Body.String())
			}
		}
		rec := dnsFailoverRequest(router, http.MethodPost, path+"/delete", `{"hosts":["entry.example"]}`)
		if rec.Code != 200 || len(f.deleted) != 1 || f.deleted[0][0] != "entry.example" || !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
			t.Fatalf("delete: %d %#v", rec.Code, f.deleted)
		}
		if rec := dnsFailoverRequest(router, http.MethodDelete, path+"/delete", ""); rec.Code != 405 {
			t.Fatal(rec.Code)
		}
	}
}

func TestDispatchAdminRoutesRequireAdminAndStrictJSON(t *testing.T) {
	f := &fakeDispatchAdmin{fakeDNSAdminService: &fakeDNSAdminService{}}
	path := "/api/v1/control/dns-failover/dispatch-entries"
	for _, identity := range []*session.Identity{nil, {ID: 1, IsAdmin: 0}, {ID: 1, IsAdmin: 1}} {
		auth := &fakeSessionService{user: identity}
		if identity == nil || identity.IsAdmin == 0 {
			auth.authErr = session.ErrUnauthorized
		}
		router := NewRouter(config.Config{AdminPath: "control"}, WithSessionService(auth), WithAdminService(f))
		rec := dnsFailoverRequest(router, http.MethodGet, path, "")
		if !auth.lastRequireAdmin {
			t.Fatal("route did not require administrator authentication")
		}
		if identity == nil || identity.IsAdmin == 0 {
			if rec.Code < 400 {
				t.Fatal("unauthorized catalog exposed")
			}
			continue
		}
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "100-200") || !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		for _, body := range []string{`{"host":"entry.example","unexpected":true}`, `{"host":"entry.example"}{}`, `{"host":"` + strings.Repeat("x", maxDNSFailoverJSONBody) + `"}`} {
			if rec := dnsFailoverRequest(router, http.MethodPut, path, body); rec.Code < 400 {
				t.Fatal("bad JSON accepted")
			}
		}
		rec = dnsFailoverRequest(router, http.MethodPut, path, `{"host":"entry.example","check_port":18443,"enabled":true,"check_interval_sec":30,"tcp_timeout_ms":1000,"probe_ids":[7]}`)
		if rec.Code != 200 || len(f.saves) != 1 || f.saves[0].CheckPort != 18443 {
			t.Fatalf("%d %#v", rec.Code, f.saves)
		}
	}
}

type fakeDispatchProbe struct {
	*fakeDNSProbeService
	dispatchReports []admin.DNSProbeResultsRequest
}

func (f *fakeDispatchProbe) ListDispatchProbeTasks(context.Context, int64) ([]admin.DNSProbeTask, error) {
	return []admin.DNSProbeTask{{TargetID: -7, CheckHost: "entry.example", CheckPort: 18443, TargetVersion: 2}}, nil
}
func (f *fakeDispatchProbe) ReportDispatchProbeResults(_ context.Context, _ int64, r admin.DNSProbeResultsRequest) (admin.DNSProbeReportResult, error) {
	f.dispatchReports = append(f.dispatchReports, r)
	return admin.DNSProbeReportResult{Accepted: len(r.Results)}, nil
}

func TestProbeTransportSeparatesDNSAndDispatchNamespaces(t *testing.T) {
	f := &fakeDispatchProbe{fakeDNSProbeService: &fakeDNSProbeService{tasks: []admin.DNSProbeTask{{TargetID: 7}}, reportResult: admin.DNSProbeReportResult{Accepted: 1, PrewarmCount: 3}}}
	router := NewRouter(config.Config{}, WithDNSProbeService(f))
	request := func(method, path, body string) string {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer good-secret")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}
	var tasks struct {
		Data []admin.DNSProbeTask `json:"data"`
	}
	if err := json.Unmarshal([]byte(request(http.MethodGet, "/api/v1/probe/tasks", "")), &tasks); err != nil {
		t.Fatal(err)
	}
	if len(tasks.Data) != 1 || tasks.Data[0].TargetID != 7 {
		t.Fatalf("%#v", tasks)
	}
	body := request(http.MethodPost, "/api/v1/probe/results", `{"results":[{"target_id":7,"result_id":"dns","success":true},{"target_id":-7,"target_version":2,"result_id":"-7-100","success":true}]}`)
	if len(f.reports) != 1 || f.reports[0].Results[0].TargetID != 7 || len(f.dispatchReports) != 0 || !strings.Contains(body, `"accepted":1`) || !strings.Contains(body, `"skipped":1`) {
		t.Fatalf("%s %#v %#v", body, f.reports, f.dispatchReports)
	}
}
