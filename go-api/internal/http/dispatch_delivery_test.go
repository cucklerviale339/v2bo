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
	calls    int
	settings admin.InvestigationSettings
}

func (s *fakeInvestigation) GetInvestigation(context.Context, int64) (admin.InvestigationView, error) {
	return admin.InvestigationView{Settings: s.settings}, nil
}
func (s *fakeInvestigation) SaveInvestigation(_ context.Context, v admin.InvestigationSettings) error {
	s.calls++
	s.settings = v
	return nil
}
func (s *fakeInvestigation) EditInvestigation(context.Context, admin.InvestigationEdit) error {
	s.calls++
	return nil
}
func TestInvestigationAdminOnlyAndStrictSettings(t *testing.T) {
	s := &fakeInvestigation{fakeDNSAdminService: &fakeDNSAdminService{}}
	path := "/api/v1/control/dns-failover/dispatch-investigation"
	router := NewRouter(config.Config{AdminPath: "control"}, WithSessionService(&fakeSessionService{authErr: session.ErrUnauthorized}), WithAdminService(s))
	for _, p := range []string{path, path + "/groups"} {
		for _, method := range []string{"GET", "PUT"} {
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
}
