package httpapi

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"forest/go-api/internal/admin"
	"forest/go-api/internal/config"
	"forest/go-api/internal/session"
	usersvc "forest/go-api/internal/user"
)

func TestDeliveredHostsExcludeSNICommentsAndEncodedNames(t *testing.T) {
	vmess := `{"add":"vm.example","port":"443","host":"cdn.example","ps":"fake.example"}`
	for _, tc := range []struct {
		body    string
		yes, no []string
	}{
		{`{"outbounds":[{"type":"vless","server":"real.example","server_port":443,"tls":{"server_name":"fake.example"}}]}`, []string{"real.example"}, []string{"fake.example"}},
		{"proxies:\n - name: fake.example\n   type: vmess\n   server: real.example\n   port: 443\n   ws-opts:\n    headers:\n     Host: cdn.example\n", []string{"real.example"}, []string{"fake.example", "cdn.example"}},
		{base64.StdEncoding.EncodeToString([]byte("vmess://" + base64.StdEncoding.EncodeToString([]byte(vmess)) + "\nvless://uuid@vless.example:443?security=tls&sni=fake.example#name\n")), []string{"vm.example", "vless.example"}, []string{"fake.example", "cdn.example"}},
		{"# failed.example\n[Proxy]\nname = trojan, real.example, 443, password=x\n", []string{"real.example"}, []string{"failed.example"}},
		{base64.StdEncoding.EncodeToString([]byte("trojan=real.example:443, password=x, tls-host=fake.example")), []string{"real.example"}, []string{"fake.example"}},
	} {
		got := deliveredEndpointHosts([]byte(tc.body))
		for _, h := range tc.yes {
			if !got[h] {
				t.Fatalf("missing %s in %v", h, got)
			}
		}
		for _, h := range tc.no {
			if got[h] {
				t.Fatalf("false host %s in %v", h, got)
			}
		}
	}
}

func TestDeliveredHostsReadActualClientPayloadFormats(t *testing.T) {
	nodes := []map[string]any{{"type": "vmess", "host": "round.example", "port": int64(443), "name": "Do not count fake.example", "network": "ws", "network_settings": map[string]any{"path": "/", "headers": map[string]any{"Host": "fake.example"}}}}
	for _, body := range []string{buildGeneralSubscribePayload("uuid", nodes), buildShadowrocketPayload(usersvc.Subscribe{UUID: "uuid"}, nodes), buildLoonPayload("uuid", nodes), buildQuantumultXPayload("uuid", nodes), buildSagerNetPayload("uuid", nodes)} {
		hosts := deliveredEndpointHosts([]byte(body))
		if !hosts["round.example"] || hosts["fake.example"] {
			t.Fatal(hosts)
		}
	}
}

type deliveryUser struct {
	usersvc.Service
	calls   int
	entries []usersvc.InvestigationDelivery
	failure bool
}

func (s *deliveryUser) RecordInvestigationDelivery(_ context.Context, _ int64, v []usersvc.InvestigationDelivery, _ int64) error {
	s.calls++
	s.entries = v
	return nil
}
func (s *deliveryUser) MarkInvestigationDeliveryFailure(context.Context) error {
	s.failure = true
	return nil
}

type failBodyWriter struct{ *httptest.ResponseRecorder }

func (w failBodyWriter) Write(p []byte) (int, error) { return 0, errors.New("disconnected") }
func TestDispatchDeliveryCreditsOnlySuccessfulActualBody(t *testing.T) {
	servers := []map[string]any{{"host": usersvc.InvestigationHost{Value: "real.example", GroupID: 5, Generation: 3}, "port": 443}, {"host": usersvc.InvestigationHost{Value: "omitted.example", GroupID: 6, Generation: 1}, "port": 443}}
	for _, mode := range []string{"ok", "error", "empty", "disconnect", "extra", "module"} {
		t.Run(mode, func(t *testing.T) {
			service := &deliveryUser{}
			var base http.ResponseWriter = httptest.NewRecorder()
			if mode == "disconnect" {
				base = failBodyWriter{base.(*httptest.ResponseRecorder)}
			}
			nodes := servers
			if mode == "extra" {
				nodes = []map[string]any{{"host": servers[0]["host"], "node_address_extra_node": int64(1)}}
			}
			w, finish := trackDispatchDelivery(base, httptest.NewRequest("GET", "/", nil), service, 42, nodes)
			switch mode {
			case "error":
				w.WriteHeader(500)
				w.Write([]byte(`{"host":"real.example","port":443}`))
			case "empty":
				w.WriteHeader(200)
			case "module":
				w.Write([]byte("#!name=real.example\n[Host]\n"))
			default:
				w.Write([]byte(`{"proxies":[{"server":"real.example","port":443}]}`))
			}
			finish()
			if mode == "ok" {
				if service.calls != 1 || len(service.entries) != 1 || service.entries[0].GroupID != 5 || service.entries[0].Generation != 3 {
					t.Fatal(service)
				}
			} else if service.calls != 0 {
				t.Fatal("false delivery", mode)
			}
		})
	}
}

type fakeInvestigation struct {
	*fakeDNSAdminService
	calls      int
	settings   admin.InvestigationSettings
	triggerErr error
	edit       admin.InvestigationEdit
}

func (s *fakeInvestigation) GetInvestigation(context.Context, int64) (admin.InvestigationView, error) {
	return admin.InvestigationView{Settings: s.settings}, nil
}
func (s *fakeInvestigation) SaveInvestigation(_ context.Context, v admin.InvestigationSettings) error {
	s.calls++
	s.settings = v
	return nil
}
func (s *fakeInvestigation) EditInvestigation(_ context.Context, v admin.InvestigationEdit) error {
	s.calls++
	s.edit = v
	return nil
}

func TestInvestigationEditExplicitMemberListAndLegacyRequest(t *testing.T) {
	s := &fakeInvestigation{fakeDNSAdminService: &fakeDNSAdminService{}}
	router := NewRouter(config.Config{AdminPath: "control"}, WithSessionService(&fakeSessionService{user: &session.Identity{ID: 1, IsAdmin: 1}}), WithAdminService(s))
	path := "/api/v1/control/dns-failover/dispatch-investigation/groups"
	r := dnsFailoverRequest(router, "PUT", path, `{"id":3,"revision":2,"name":"稳定组","host":"192.0.2.10","user_ids":["11","12"]}`)
	if r.Code != 200 || s.calls != 1 || s.edit.UserIDs == nil || len(*s.edit.UserIDs) != 2 || (*s.edit.UserIDs)[1] != "12" {
		t.Fatal(r.Code, r.Body.String(), s.edit)
	}
	for _, body := range []string{`{"id":3,"revision":2,"user_ids":[11,12]}`, `{"id":3,"revision":2,"user_ids":"11,12"}`, `{"id":3,"revision":2,"unknown":true}`} {
		if r := dnsFailoverRequest(router, "PUT", path, body); r.Code != 400 || s.calls != 1 {
			t.Fatal(r.Code, r.Body.String(), s.calls)
		}
	}
	r = dnsFailoverRequest(router, "PUT", path, `{"id":3,"revision":2,"name":"仅改名","host":"192.0.2.10"}`)
	if r.Code != 200 || s.edit.UserIDs != nil {
		t.Fatal("legacy edit changed membership", r.Code, s.edit)
	}
}
func (s *fakeInvestigation) ConfirmInvestigation(context.Context, admin.InvestigationAction) error {
	s.calls++
	return nil
}
func (s *fakeInvestigation) TriggerInvestigation(context.Context, admin.InvestigationAction) error {
	s.calls++
	return s.triggerErr
}

func TestInvestigationTriggerBusyAndDeadlineResponses(t *testing.T) {
	for _, tc := range []struct {
		err     error
		code    int
		message string
	}{{admin.ErrInvestigationBusy, http.StatusConflict, "其他入口任务正在处理"}, {context.DeadlineExceeded, http.StatusGatewayTimeout, "请刷新分组状态"}} {
		s := &fakeInvestigation{fakeDNSAdminService: &fakeDNSAdminService{}, triggerErr: tc.err}
		router := NewRouter(config.Config{AdminPath: "control"}, WithSessionService(&fakeSessionService{user: &session.Identity{ID: 1, IsAdmin: 1}}), WithAdminService(s))
		r := dnsFailoverRequest(router, "POST", "/api/v1/control/dns-failover/dispatch-investigation/trigger", `{"id":1,"revision":1}`)
		if r.Code != tc.code || !strings.Contains(r.Body.String(), tc.message) || s.calls != 1 {
			t.Fatal(r.Code, r.Body.String(), s.calls)
		}
		if tc.code == http.StatusConflict && r.Header().Get("Retry-After") != "2" {
			t.Fatal("missing retry hint", r.Header())
		}
	}
}
func TestInvestigationAdminOnlyAndStrictSettings(t *testing.T) {
	s := &fakeInvestigation{fakeDNSAdminService: &fakeDNSAdminService{}}
	path := "/api/v1/control/dns-failover/dispatch-investigation"
	router := NewRouter(config.Config{AdminPath: "control"}, WithSessionService(&fakeSessionService{authErr: session.ErrUnauthorized}), WithAdminService(s))
	for _, p := range []string{path, path + "/groups", path + "/confirm", path + "/trigger"} {
		for _, method := range []string{"GET", "PUT", "POST"} {
			if r := dnsFailoverRequest(router, method, p, `{}`); r.Code != 403 || s.calls != 0 {
				t.Fatal(r.Code)
			}
		}
	}
	router = NewRouter(config.Config{AdminPath: "control"}, WithSessionService(&fakeSessionService{user: &session.Identity{ID: 1, IsAdmin: 1}}), WithAdminService(s))
	for _, body := range []string{`{"enabled":true,"surprise":1}`, `{"enabled":"true"}`, `{} {}`} {
		if r := dnsFailoverRequest(router, "PUT", path, body); r.Code != 400 || s.calls != 0 {
			t.Fatal(r.Code, body)
		}
	}
	if r := dnsFailoverRequest(router, "PUT", path, `{"enabled":true,"revision":1,"entry_window_minutes":20,"global_window_minutes":60,"global_max":3}`); r.Code != 200 || s.calls != 1 || !s.settings.Enabled || !strings.Contains(r.Header().Get("Cache-Control"), "no-store") {
		t.Fatal(r.Code, s.calls, s.settings, r.Header(), r.Body.String())
	}
	if r := dnsFailoverRequest(router, "POST", path, `{}`); r.Code != 405 {
		t.Fatal(r.Code)
	}
	for _, action := range []string{"confirm", "trigger"} {
		before := s.calls
		if r := dnsFailoverRequest(router, "GET", path+"/"+action, ""); r.Code != 405 || s.calls != before {
			t.Fatal(r.Code, r.Body.String())
		}
		if r := dnsFailoverRequest(router, "POST", path+"/"+action, `{"id":1,"revision":1,"force":true}`); r.Code != 400 || s.calls != before {
			t.Fatal(r.Code, r.Body.String())
		}
		if r := dnsFailoverRequest(router, "POST", path+"/"+action, `{"id":1,"revision":1}`); r.Code != 200 || s.calls != before+1 {
			t.Fatal(r.Code, r.Body.String())
		}
	}
}
