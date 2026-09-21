package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"forest/go-api/internal/config"
	"forest/go-api/internal/nodeapi"
	"forest/go-api/internal/session"
	"forest/go-api/internal/user"
)

type fakeClientEntryRemoteResolver struct {
	ipsByCode map[string][]string
	lastGroup user.ClientEntryGroup
	err       error
}

func (f *fakeClientEntryRemoteResolver) ResolveRemoteIPs(_ context.Context, group user.ClientEntryGroup) ([]string, error) {
	f.lastGroup = group
	if f.err != nil {
		return nil, f.err
	}
	values := f.ipsByCode[group.Code]
	result := make([]string, 0, len(values))
	result = append(result, values...)
	return result, nil
}

func TestRouterClientAppGetVersionEndpoint(t *testing.T) {
	t.Setenv("WINDOWS_VERSION", "1.2.3")
	t.Setenv("WINDOWS_DOWNLOAD_URL", "https://example.com/windows.exe")
	t.Setenv("MACOS_VERSION", "2.3.4")
	t.Setenv("MACOS_DOWNLOAD_URL", "https://example.com/macos.dmg")
	t.Setenv("ANDROID_VERSION", "3.4.5")
	t.Setenv("ANDROID_DOWNLOAD_URL", "https://example.com/android.apk")

	router := NewRouter(config.Load())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/app/getVersion", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected json body: %v", err)
	}

	data, ok := payload["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected data object, got %#v", payload["data"])
	}
	if data["windows_version"] != "1.2.3" || data["android_download_url"] != "https://example.com/android.apk" {
		t.Fatalf("unexpected version payload: %#v", data)
	}
}

func TestRouterClientAppGetConfigEndpoint(t *testing.T) {
	userService := &fakeUserService{
		resolvedClientUserID: 10,
		servers: []map[string]any{
			{
				"type":    "vmess",
				"name":    "VMess-1",
				"host":    "node.example.com",
				"port":    int64(443),
				"network": "ws",
				"tls":     int64(1),
				"tls_settings": map[string]any{
					"server_name": "node.example.com",
				},
				"network_settings": map[string]any{
					"path": "/ws",
					"headers": map[string]any{
						"Host": "node.example.com",
					},
				},
			},
		},
	}
	router := NewRouter(config.Config{PublicDir: "../public"}, WithUserService(userService))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/app/getConfig?token=token-1", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "yaml") {
		t.Fatalf("expected yaml content type, got %q", contentType)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "VMess-1") || !strings.Contains(body, "proxies:") {
		t.Fatalf("expected generated clash app config, got %q", body)
	}
	if userService.lastClientToken != "token-1" || userService.lastServerUA != "" {
		t.Fatalf("unexpected client auth/request state: token=%q ua=%q", userService.lastClientToken, userService.lastServerUA)
	}
}

func TestRouterUserForestRuntimeProfileEndpoint(t *testing.T) {
	sessionService := &fakeSessionService{user: &session.Identity{ID: 10}}
	userService := &fakeUserService{
		subscribe: user.Subscribe{
			Token: "client-token-1",
		},
		servers: []map[string]any{
			{
				"id":      int64(11),
				"type":    "vmess",
				"name":    "JP-1",
				"host":    "jp.example.com",
				"port":    int64(443),
				"network": "ws",
				"tls":     int64(1),
				"tls_settings": map[string]any{
					"server_name": "jp.example.com",
				},
				"network_settings": map[string]any{
					"path": "/ws",
					"headers": map[string]any{
						"Host": "jp.example.com",
					},
				},
			},
			{
				"id":          int64(12),
				"type":        "trojan",
				"name":        "US-1",
				"host":        "us.example.com",
				"port":        int64(443),
				"network":     "tcp",
				"server_name": "us.example.com",
			},
		},
		clientEntryGroups: []user.ClientEntryGroup{
			{
				ID:              int64(7),
				Code:            "asia",
				Name:            "Asia",
				DisplayName:     "Asia Entry",
				Strategy:        "sticky-low-latency",
				HideMemberNodes: true,
				IPs: []user.ClientEntryGroupIP{
					{IP: "1.1.1.1"},
					{IP: "8.8.8.8"},
				},
				Members: []user.ClientEntryGroupMember{
					{ServerType: "vmess", ServerID: int64(11)},
				},
			},
		},
	}
	router := NewRouter(
		config.Config{AppURL: "https://panel.example.com"},
		WithSessionService(sessionService),
		WithUserService(userService),
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/user/forest/runtime-profile?cap=entry-provider-v1", nil)
	req.Header.Set("Authorization", "jwt-user")
	req.Header.Set("User-Agent", "forest-desktop/1.0")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected json body: %v", err)
	}
	data, ok := payload["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected data object, got %#v", payload["data"])
	}
	if data["capability"] != "entry-provider-v1" {
		t.Fatalf("unexpected capability: %#v", data["capability"])
	}
	entryGroups, ok := data["entry_groups"].([]any)
	if !ok || len(entryGroups) != 1 {
		t.Fatalf("expected one entry group, got %#v", data["entry_groups"])
	}
	group, ok := entryGroups[0].(map[string]any)
	if !ok {
		t.Fatalf("expected entry group object, got %#v", entryGroups[0])
	}
	if group["code"] != "asia" || group["display_name"] != "Asia Entry" {
		t.Fatalf("unexpected runtime entry group: %#v", group)
	}
	if group["strategy"] != "ordered-fallback" {
		t.Fatalf("unexpected normalized runtime strategy: %#v", group["strategy"])
	}
	if group["provider_url"] != "https://panel.example.com/api/v1/client/forest/entry-provider?token=client-token-1&code=asia" {
		t.Fatalf("unexpected provider_url: %#v", group["provider_url"])
	}
	memberNames, ok := group["member_names"].([]any)
	if !ok || len(memberNames) != 1 || memberNames[0] != "JP-1" {
		t.Fatalf("unexpected member names: %#v", group["member_names"])
	}
	if userService.lastServerUA != "forest-desktop/1.0" {
		t.Fatalf("expected runtime profile to forward ua, got %q", userService.lastServerUA)
	}
}

func TestRouterClientForestEntryProviderEndpoint(t *testing.T) {
	userService := &fakeUserService{
		resolvedClientUserID: int64(10),
		subscribe: user.Subscribe{
			UUID: "user-uuid",
		},
		servers: []map[string]any{
			{
				"id":      int64(11),
				"type":    "vmess",
				"name":    "JP-1",
				"host":    "jp.example.com",
				"port":    int64(443),
				"network": "ws",
				"tls":     int64(1),
				"tls_settings": map[string]any{
					"server_name": "jp.example.com",
				},
				"network_settings": map[string]any{
					"path": "/ws",
					"headers": map[string]any{
						"Host": "jp.example.com",
					},
				},
			},
			{
				"id":          int64(12),
				"type":        "trojan",
				"name":        "US-1",
				"host":        "us.example.com",
				"port":        int64(443),
				"network":     "tcp",
				"server_name": "us.example.com",
			},
		},
		clientEntryGroups: []user.ClientEntryGroup{
			{
				ID:          int64(7),
				Code:        "asia",
				Name:        "Asia",
				DisplayName: "Asia Entry",
				Strategy:    "sticky-low-latency",
				IPs: []user.ClientEntryGroupIP{
					{IP: "1.1.1.1"},
					{IP: "8.8.8.8"},
				},
				Members: []user.ClientEntryGroupMember{
					{ServerType: "vmess", ServerID: int64(11)},
				},
			},
		},
	}
	router := NewRouter(config.Config{}, WithUserService(userService))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/forest/entry-provider?token=token-1&code=asia", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "yaml") {
		t.Fatalf("expected yaml content type, got %q", contentType)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "proxies:") || !strings.Contains(body, "JP-1") {
		t.Fatalf("expected forest provider yaml, got %q", body)
	}
	if strings.Contains(body, "US-1") {
		t.Fatalf("expected provider yaml to exclude non-member nodes, got %q", body)
	}
	if !strings.Contains(body, "1.1.1.1") || !strings.Contains(body, "8.8.8.8") {
		t.Fatalf("expected provider yaml to include entry ips, got %q", body)
	}
	if userService.lastClientToken != "token-1" {
		t.Fatalf("expected provider endpoint to use client token, got %q", userService.lastClientToken)
	}
}

func TestRouterUserForestRuntimeProfileEndpointIncludesRemoteOnlyEntryGroup(t *testing.T) {
	sessionService := &fakeSessionService{user: &session.Identity{ID: 10}}
	userService := &fakeUserService{
		subscribe: user.Subscribe{
			Token: "client-token-1",
		},
		servers: []map[string]any{
			{
				"id":      int64(11),
				"type":    "vmess",
				"name":    "JP-1",
				"host":    "jp.example.com",
				"port":    int64(443),
				"network": "ws",
				"tls":     int64(1),
				"tls_settings": map[string]any{
					"server_name": "jp.example.com",
				},
				"network_settings": map[string]any{
					"path": "/ws",
					"headers": map[string]any{
						"Host": "jp.example.com",
					},
				},
			},
		},
		clientEntryGroups: []user.ClientEntryGroup{
			{
				ID:                int64(7),
				Code:              "asia",
				Name:              "Asia",
				DisplayName:       "Asia Entry",
				Strategy:          "sticky-low-latency",
				HideMemberNodes:   true,
				RemoteEnabled:     true,
				RemoteHost:        "192.0.2.10",
				RemoteSSHPort:     2222,
				RemoteSSHUser:     "root",
				RemoteSSHPassword: "secret",
				RemoteGroupRef:    "专线直出 (#15)",
				RemoteExcludeNames: []string{
					"alice",
				},
				RemoteRefreshSec: 300,
				Members: []user.ClientEntryGroupMember{
					{ServerType: "vmess", ServerID: int64(11)},
				},
			},
		},
	}
	resolver := &fakeClientEntryRemoteResolver{
		ipsByCode: map[string][]string{
			"asia": {"8.8.8.8"},
		},
	}
	router := NewRouter(
		config.Config{AppURL: "https://panel.example.com"},
		WithSessionService(sessionService),
		WithUserService(userService),
		WithClientEntryRemoteResolver(resolver),
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/user/forest/runtime-profile?cap=entry-provider-v1", nil)
	req.Header.Set("Authorization", "jwt-user")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected json body: %v", err)
	}
	data, ok := payload["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected data object, got %#v", payload["data"])
	}
	entryGroups, ok := data["entry_groups"].([]any)
	if !ok || len(entryGroups) != 1 {
		t.Fatalf("expected one remote-backed entry group, got %#v", data["entry_groups"])
	}
	if resolver.lastGroup.Code != "asia" || resolver.lastGroup.RemoteGroupRef != "专线直出 (#15)" || len(resolver.lastGroup.RemoteExcludeNames) != 1 || resolver.lastGroup.RemoteExcludeNames[0] != "alice" {
		t.Fatalf("unexpected resolver contract: %#v", resolver.lastGroup)
	}
}

func TestRouterClientForestEntryProviderEndpointMergesRemoteIPs(t *testing.T) {
	userService := &fakeUserService{
		resolvedClientUserID: int64(10),
		subscribe: user.Subscribe{
			UUID: "user-uuid",
		},
		servers: []map[string]any{
			{
				"id":      int64(11),
				"type":    "vmess",
				"name":    "JP-1",
				"host":    "jp.example.com",
				"port":    int64(443),
				"network": "ws",
				"tls":     int64(1),
				"tls_settings": map[string]any{
					"server_name": "jp.example.com",
				},
				"network_settings": map[string]any{
					"path": "/ws",
					"headers": map[string]any{
						"Host": "jp.example.com",
					},
				},
			},
		},
		clientEntryGroups: []user.ClientEntryGroup{
			{
				ID:                int64(7),
				Code:              "asia",
				Name:              "Asia",
				DisplayName:       "Asia Entry",
				Strategy:          "sticky-low-latency",
				RemoteEnabled:     true,
				RemoteHost:        "192.0.2.10",
				RemoteSSHPort:     2222,
				RemoteSSHUser:     "root",
				RemoteSSHPassword: "secret",
				RemoteGroupRef:    "专线直出 (#15)",
				RemoteExcludeNames: []string{
					"alice",
				},
				RemoteRefreshSec: 300,
				IPs: []user.ClientEntryGroupIP{
					{IP: "1.1.1.1"},
				},
				Members: []user.ClientEntryGroupMember{
					{ServerType: "vmess", ServerID: int64(11)},
				},
			},
		},
	}
	resolver := &fakeClientEntryRemoteResolver{
		ipsByCode: map[string][]string{
			"asia": {"8.8.8.8", "1.1.1.1"},
		},
	}
	router := NewRouter(
		config.Config{},
		WithUserService(userService),
		WithClientEntryRemoteResolver(resolver),
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/forest/entry-provider?token=token-1&code=asia", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "JP-1 @1.1.1.1") || !strings.Contains(body, "JP-1 @8.8.8.8") {
		t.Fatalf("expected provider yaml to include merged manual + remote ips, got %q", body)
	}
	if strings.Count(body, "JP-1 @1.1.1.1") != 1 {
		t.Fatalf("expected provider yaml to dedupe duplicate ips, got %q", body)
	}
	if resolver.lastGroup.Code != "asia" || resolver.lastGroup.RemoteGroupRef != "专线直出 (#15)" {
		t.Fatalf("unexpected resolver contract: %#v", resolver.lastGroup)
	}
}

func TestRouterClientForestEntryProviderEndpointKeepsManualDomains(t *testing.T) {
	userService := &fakeUserService{
		resolvedClientUserID: int64(10),
		subscribe: user.Subscribe{
			UUID: "user-uuid",
		},
		servers: []map[string]any{
			{
				"id":      int64(11),
				"type":    "vmess",
				"name":    "JP-1",
				"host":    "jp.example.com",
				"port":    int64(443),
				"network": "ws",
				"tls":     int64(1),
				"tls_settings": map[string]any{
					"server_name": "jp.example.com",
				},
				"network_settings": map[string]any{
					"path": "/ws",
					"headers": map[string]any{
						"Host": "jp.example.com",
					},
				},
			},
		},
		clientEntryGroups: []user.ClientEntryGroup{
			{
				ID:          int64(7),
				Code:        "asia",
				Name:        "Asia",
				DisplayName: "Asia Entry",
				Strategy:    "ordered-fallback",
				IPs: []user.ClientEntryGroupIP{
					{IP: "entry-a.example.com"},
				},
				Members: []user.ClientEntryGroupMember{
					{ServerType: "vmess", ServerID: int64(11)},
				},
			},
		},
	}
	router := NewRouter(config.Config{}, WithUserService(userService))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/forest/entry-provider?token=token-1&code=asia", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "entry-a.example.com") {
		t.Fatalf("expected provider yaml to keep manual domain entry, got %q", body)
	}
}

func TestRouterClientSubscribeEndpoint(t *testing.T) {
	userService := &fakeUserService{
		resolvedClientUserID: 10,
		subscribe: user.Subscribe{
			U:              11,
			D:              22,
			TransferEnable: 100,
			ExpiredAt:      int64Ptr(1234567890),
			UUID:           "user-uuid",
		},
		servers: []map[string]any{
			{
				"type":    "vmess",
				"name":    "VMess-1",
				"host":    "node.example.com",
				"port":    int64(443),
				"network": "ws",
				"tls":     int64(1),
				"tls_settings": map[string]any{
					"server_name": "node.example.com",
				},
				"network_settings": map[string]any{
					"path": "/ws",
					"headers": map[string]any{
						"Host": "node.example.com",
					},
				},
			},
			{
				"type":        "trojan",
				"name":        "Trojan-1",
				"host":        "trojan.example.com",
				"port":        int64(443),
				"network":     "tcp",
				"tls":         int64(1),
				"server_name": "trojan.example.com",
			},
		},
	}
	router := NewRouter(config.Config{AppName: "Forest"}, WithUserService(userService))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/subscribe?token=token-1", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("subscription-userinfo"); got != "upload=11; download=22; total=100; expire=1234567890" {
		t.Fatalf("unexpected subscription-userinfo header: %q", got)
	}
	if got := rec.Header().Get("content-disposition"); got != "" {
		t.Fatalf("expected general subscribe to avoid attachment header, got %q", got)
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rec.Body.String()))
	if err != nil {
		t.Fatalf("expected base64 body: %v", err)
	}
	body := string(decoded)
	if !strings.Contains(body, "vmess://") || !strings.Contains(body, "trojan://") {
		t.Fatalf("unexpected subscribe payload: %q", body)
	}
}

func compatibleSubscribeUserService(servers []map[string]any) *fakeUserService {
	return &fakeUserService{
		resolvedClientUserID: 10,
		subscribe: user.Subscribe{
			U:              11,
			D:              22,
			TransferEnable: 100,
			ExpiredAt:      int64Ptr(1234567890),
			UUID:           "user-uuid",
		},
		servers: servers,
	}
}

func compatibleVmessServer() map[string]any {
	return map[string]any{
		"type":    "vmess",
		"name":    "VMess-1",
		"host":    "node.example.com",
		"port":    int64(443),
		"network": "ws",
		"tls":     int64(1),
		"tls_settings": map[string]any{
			"server_name": "node.example.com",
		},
		"network_settings": map[string]any{
			"path": "/ws",
			"headers": map[string]any{
				"Host": "node.example.com",
			},
		},
	}
}

func compatibleShadowsocksServer() map[string]any {
	return map[string]any{
		"id":     int64(7),
		"type":   "shadowsocks",
		"name":   "SS-1",
		"host":   "ss.example.com",
		"port":   int64(8388),
		"cipher": "aes-256-gcm",
	}
}

func TestRouterClientSubscribeLoonEndpointUsesPlainTextProfile(t *testing.T) {
	router := NewRouter(config.Config{AppName: "Forest"}, WithUserService(compatibleSubscribeUserService([]map[string]any{compatibleVmessServer()})))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/subscribe?token=token-1&flag=loon", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "text/plain") {
		t.Fatalf("expected loon subscribe to return text/plain, got %q", contentType)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "VMess-1=vmess,node.example.com,443") || strings.Contains(body, "vmess://") {
		t.Fatalf("expected loon plain text profile, got %q", body)
	}
}

func TestRouterClientSubscribeQuantumultXEndpointUsesDedicatedBase64Profile(t *testing.T) {
	router := NewRouter(config.Config{AppName: "Forest"}, WithUserService(compatibleSubscribeUserService([]map[string]any{compatibleVmessServer()})))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/subscribe?token=token-1&flag=quantumult%20x", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rec.Body.String()))
	if err != nil {
		t.Fatalf("expected quantumult x base64 body: %v", err)
	}
	body := string(decoded)
	if !strings.Contains(body, "vmess=node.example.com:443") || strings.Contains(body, "vmess://") {
		t.Fatalf("expected quantumult x line profile, got %q", body)
	}
}

func TestRouterClientSubscribeShadowsocksEndpointUsesSIP008(t *testing.T) {
	router := NewRouter(config.Config{AppName: "Forest"}, WithUserService(compatibleSubscribeUserService([]map[string]any{compatibleShadowsocksServer()})))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/subscribe?token=token-1&flag=shadowsocks", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "application/json") {
		t.Fatalf("expected shadowsocks subscribe to return json, got %q", contentType)
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode sip008 payload: %v", err)
	}
	servers := payload["servers"].([]any)
	if len(servers) != 1 {
		t.Fatalf("expected one sip008 server, got %#v", servers)
	}
	server := servers[0].(map[string]any)
	if server["remarks"] != "SS-1" || server["server"] != "ss.example.com" {
		t.Fatalf("unexpected sip008 server: %#v", server)
	}
}

func TestRouterClientSubscribeStashEndpointUsesStashTemplate(t *testing.T) {
	router := NewRouter(config.Config{AppName: "Forest", PublicDir: "../public"}, WithUserService(compatibleSubscribeUserService([]map[string]any{compatibleVmessServer()})))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/subscribe?token=token-1&flag=stash", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "mixed-port: 7890") || !strings.Contains(body, "VMess-1") {
		t.Fatalf("expected stash yaml profile from stash template, got %q", body)
	}
}

func TestRouterClientSubscribeSagerNetEndpointUsesGeneralURIBase64(t *testing.T) {
	router := NewRouter(config.Config{AppName: "Forest"}, WithUserService(compatibleSubscribeUserService([]map[string]any{compatibleVmessServer()})))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/subscribe?token=token-1&flag=sagernet", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rec.Body.String()))
	if err != nil {
		t.Fatalf("expected sagernet base64 body: %v", err)
	}
	if body := string(decoded); !strings.Contains(body, "vmess://") {
		t.Fatalf("expected sagernet URI payload, got %q", body)
	}
}

func TestRouterClientSubscribeV2RayTunEndpointKeepsDownloadHeaders(t *testing.T) {
	router := NewRouter(config.Config{AppName: "Forest"}, WithUserService(compatibleSubscribeUserService([]map[string]any{compatibleVmessServer()})))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/subscribe?token=token-1&flag=v2raytun", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Disposition"); got != `attachment; filename="Forest"` {
		t.Fatalf("expected v2raytun attachment header, got %q", got)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rec.Body.String()))
	if err != nil {
		t.Fatalf("expected v2raytun base64 body: %v", err)
	}
	if body := string(decoded); !strings.Contains(body, "vmess://") {
		t.Fatalf("expected v2raytun URI payload, got %q", body)
	}
}

func TestRouterClientSubscribeClashEndpointUsesAttachmentHeader(t *testing.T) {
	userService := &fakeUserService{
		resolvedClientUserID: 10,
		subscribe: user.Subscribe{
			U:              11,
			D:              22,
			TransferEnable: 100,
			ExpiredAt:      int64Ptr(1234567890),
			UUID:           "user-uuid",
		},
		servers: []map[string]any{
			{
				"type":    "vmess",
				"name":    "VMess-1",
				"host":    "node.example.com",
				"port":    int64(443),
				"network": "ws",
				"tls":     int64(1),
				"tls_settings": map[string]any{
					"server_name": "node.example.com",
				},
				"network_settings": map[string]any{
					"path": "/ws",
					"headers": map[string]any{
						"Host": "node.example.com",
					},
				},
			},
		},
	}
	router := NewRouter(config.Config{AppName: "Forest", PublicDir: "../public"}, WithUserService(userService))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/subscribe?token=token-1&flag=clash", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("content-disposition"); !strings.Contains(got, "attachment;") {
		t.Fatalf("expected clash subscribe to keep attachment header, got %q", got)
	}
	if got := rec.Header().Get("profile-title"); got != "base64:"+base64.StdEncoding.EncodeToString([]byte("Forest")) {
		t.Fatalf("expected clash subscribe to keep legacy profile-title header, got %q", got)
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "yaml") {
		t.Fatalf("expected yaml content type, got %q", contentType)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "proxies:") {
		t.Fatalf("expected clash yaml body, got %q", body)
	}
	if strings.Contains(body, "38.207.164.191") || strings.Contains(body, "apt-hcloud-doh") {
		t.Fatalf("clash subscribe should not include private DoH, got %q", body)
	}
}

func TestBuildSubscribeURIJuicityV2node(t *testing.T) {
	uri := buildSubscribeURI("user-uuid", map[string]any{
		"type":               "v2node",
		"protocol":           "juicity",
		"name":               "Juicity 1",
		"host":               "j.example.com",
		"port":               int64(443),
		"congestion_control": "bbr",
		"tls_settings":       map[string]any{"server_name": "j.example.com", "allow_insecure": true},
	})

	if !strings.HasPrefix(uri, "juicity://user-uuid:user-uuid@j.example.com:443?") {
		t.Fatalf("expected juicity uri with uuid auth, got %q", uri)
	}
	if !strings.Contains(uri, "congestion_control=bbr") || !strings.Contains(uri, "sni=j.example.com") || !strings.Contains(uri, "allow_insecure=1") || !strings.Contains(uri, "#Juicity%201") {
		t.Fatalf("expected juicity query/name fields, got %q", uri)
	}
}

func TestBuildSubscribeURIMieruV2node(t *testing.T) {
	uri := buildSubscribeURI("user-uuid", map[string]any{
		"type":             "v2node",
		"protocol":         "mieru",
		"name":             "Mieru 1",
		"host":             "m.example.com",
		"port":             int64(2999),
		"network_settings": map[string]any{"transport": "UDP", "mtu": int64(1280), "multiplexing": "MULTIPLEXING_LOW"},
	})

	if !strings.HasPrefix(uri, "mieru://user-uuid:user-uuid@m.example.com:2999?") {
		t.Fatalf("expected mieru uri with uuid auth, got %q", uri)
	}
	if !strings.Contains(uri, "transport=UDP") || !strings.Contains(uri, "mtu=1280") || !strings.Contains(uri, "multiplexing=MULTIPLEXING_LOW") || !strings.Contains(uri, "#Mieru%201") {
		t.Fatalf("expected mieru query/name fields, got %q", uri)
	}
}

func TestRouterClientSubscribeClashEndpointIncludesMetaProtocols(t *testing.T) {
	userService := &fakeUserService{
		resolvedClientUserID: 10,
		subscribe: user.Subscribe{
			U:              11,
			D:              22,
			TransferEnable: 100,
			ExpiredAt:      int64Ptr(1234567890),
			UUID:           "user-uuid",
		},
		servers: []map[string]any{
			{
				"type":    "vless",
				"name":    "VLESS-1",
				"host":    "vless.example.com",
				"port":    int64(443),
				"network": "ws",
				"tls":     int64(1),
				"tls_settings": map[string]any{
					"server_name": "vless.example.com",
					"fingerprint": "chrome",
				},
				"network_settings": map[string]any{
					"path": "/ws",
					"headers": map[string]any{
						"Host": "vless.example.com",
					},
				},
			},
			{
				"type":           "tuic",
				"name":           "TUIC-1",
				"host":           "tuic.example.com",
				"port":           int64(443),
				"server_name":    "tuic.example.com",
				"udp_relay_mode": "native",
			},
			{
				"type":          "hysteria",
				"version":       int64(2),
				"name":          "HY2-1",
				"host":          "hy2.example.com",
				"port":          int64(443),
				"server_name":   "hy2.example.com",
				"up_mbps":       int64(30),
				"down_mbps":     int64(200),
				"obfs":          "salamander",
				"obfs_password": "hy-pass",
			},
			{
				"type":        "anytls",
				"name":        "AnyTLS-1",
				"host":        "anytls.example.com",
				"port":        int64(443),
				"server_name": "anytls.example.com",
				"tls_settings": map[string]any{
					"allow_insecure": true,
				},
			},
		},
	}
	router := NewRouter(config.Config{AppName: "Forest", PublicDir: "../public"}, WithUserService(userService))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/subscribe?token=token-1&flag=clash", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, name := range []string{"VLESS-1", "TUIC-1", "HY2-1", "AnyTLS-1"} {
		if !strings.Contains(body, name) {
			t.Fatalf("expected clash yaml to include %s, got %q", name, body)
		}
	}
}

func TestRouterClientSubscribeReqIOSUserAgentUsesYAMLProfile(t *testing.T) {
	userService := &fakeUserService{
		resolvedClientUserID: 10,
		subscribe: user.Subscribe{
			U:              11,
			D:              22,
			TransferEnable: 100,
			ExpiredAt:      int64Ptr(1234567890),
			UUID:           "user-uuid",
		},
		servers: []map[string]any{
			{
				"type":    "vmess",
				"name":    "VMess-1",
				"host":    "node.example.com",
				"port":    int64(443),
				"network": "ws",
				"tls":     int64(1),
				"tls_settings": map[string]any{
					"server_name": "node.example.com",
				},
				"network_settings": map[string]any{
					"path": "/ws",
					"headers": map[string]any{
						"Host": "node.example.com",
					},
				},
			},
		},
	}
	router := NewRouter(config.Config{AppName: "Forest", PublicDir: "../public"}, WithUserService(userService))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/subscribe?token=token-1", nil)
	req.Header.Set("User-Agent", "req-ios")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "yaml") {
		t.Fatalf("expected req-ios subscribe to return yaml, got %q with body %q", contentType, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "proxies:") {
		t.Fatalf("expected req-ios subscribe body to be clash-like yaml, got %q", rec.Body.String())
	}
}

func TestRouterClientSubscribeSurgeEndpointUsesManagedProfile(t *testing.T) {
	userService := &fakeUserService{
		resolvedClientUserID: 10,
		subscribe: user.Subscribe{
			U:              11,
			D:              22,
			TransferEnable: 100,
			ExpiredAt:      int64Ptr(1234567890),
			UUID:           "user-uuid",
		},
		servers: []map[string]any{
			{
				"type":    "vmess",
				"name":    "VMess-1",
				"host":    "node.example.com",
				"port":    int64(443),
				"network": "ws",
				"tls":     int64(1),
				"tlsSettings": map[string]any{
					"serverName": "node.example.com",
				},
				"networkSettings": map[string]any{
					"path": "/ws",
					"headers": map[string]any{
						"Host": "node.example.com",
					},
				},
			},
		},
	}
	router := NewRouter(config.Config{AppName: "Forest", AppURL: "https://panel.example.com"}, WithUserService(userService))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/subscribe?token=token-1&flag=surge", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "#!MANAGED-CONFIG https://panel.example.com/api/v1/client/subscribe?token=token-1&flag=surge") ||
		!strings.Contains(body, "[Proxy]") ||
		!strings.Contains(body, "VMess-1=vmess") {
		t.Fatalf("expected surge profile body, got %q", body)
	} else if strings.Contains(body, "38.207.164.191") || strings.Contains(body, "apt-hcloud-doh") {
		t.Fatalf("surge profile should not include private DoH, got %q", body)
	}
}

func TestRouterClientSubscribeSurfboardEndpointUsesManagedProfile(t *testing.T) {
	userService := &fakeUserService{
		resolvedClientUserID: 10,
		subscribe: user.Subscribe{
			U:              11,
			D:              22,
			TransferEnable: 100,
			ExpiredAt:      int64Ptr(1234567890),
			UUID:           "user-uuid",
		},
		servers: []map[string]any{
			{
				"type":    "trojan",
				"name":    "Trojan-1",
				"host":    "trojan.example.com",
				"port":    int64(443),
				"network": "tcp",
				"tls":     int64(1),
				"tls_settings": map[string]any{
					"server_name": "trojan.example.com",
				},
			},
			{
				"type":        "anytls",
				"name":        "Surfboard-AnyTLS",
				"host":        "anytls.example.com",
				"port":        int64(443),
				"server_name": "sni.example.com",
				"tls_settings": map[string]any{
					"allow_insecure": true,
				},
			},
		},
	}
	router := NewRouter(config.Config{AppName: "Forest", AppURL: "https://panel.example.com"}, WithUserService(userService))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/subscribe?token=token-1&flag=surfboard", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "#!MANAGED-CONFIG https://panel.example.com/api/v1/client/subscribe?token=token-1&flag=surfboard") ||
		!strings.Contains(body, "[Proxy]") ||
		!strings.Contains(body, "Trojan-1=trojan") ||
		!strings.Contains(body, "Surfboard-AnyTLS=anytls,anytls.example.com,443,user-uuid,skip-cert-verify=true,sni=sni.example.com,udp-relay=true") {
		t.Fatalf("expected surfboard profile body, got %q", body)
	}
}

func TestRouterClientSubscribeSingboxFlagUsesJSONProfile(t *testing.T) {
	userService := &fakeUserService{
		resolvedClientUserID: 10,
		subscribe: user.Subscribe{
			U:              11,
			D:              22,
			TransferEnable: 100,
			ExpiredAt:      int64Ptr(1234567890),
			UUID:           "user-uuid",
		},
		servers: []map[string]any{
			{
				"type":    "vmess",
				"name":    "VMess-1",
				"host":    "node.example.com",
				"port":    int64(443),
				"network": "ws",
				"tls":     int64(1),
				"tls_settings": map[string]any{
					"server_name": "node.example.com",
				},
				"network_settings": map[string]any{
					"path": "/ws",
				},
			},
		},
	}
	router := NewRouter(config.Config{AppName: "Forest"}, WithUserService(userService))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/subscribe?token=token-1&flag=sing", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "application/json") {
		t.Fatalf("expected sing-box subscribe to return json, got %q with body %q", contentType, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "\"outbounds\"") || !strings.Contains(body, "\"VMess-1\"") || !strings.Contains(body, "\"tag\":\"direct\"") {
		t.Fatalf("expected sing-box json body, got %q", body)
	}
	if strings.Contains(body, "38.207.164.191") || strings.Contains(body, "apt-hcloud-doh") {
		t.Fatalf("sing-box profile should not include private DoH, got %q", body)
	}
}

func TestRouterClientSubscribeSingboxAptHcloudNodeUsesLocalDomainResolver(t *testing.T) {
	userService := &fakeUserService{
		resolvedClientUserID: 10,
		subscribe: user.Subscribe{
			UUID: "user-uuid",
		},
		servers: []map[string]any{
			{
				"type":   "shadowsocks",
				"name":   "AptNode",
				"host":   "hk.apt-hcloud.dev",
				"port":   int64(443),
				"cipher": "aes-128-gcm",
			},
		},
	}
	router := NewRouter(config.Config{AppName: "Forest"}, WithUserService(userService))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/subscribe?token=token-1&flag=sing", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "\"server\":\"hk.apt-hcloud.dev\"") ||
		!strings.Contains(body, "\"domain_resolver\":\"local\"") ||
		strings.Contains(body, "apt-hcloud-doh") ||
		strings.Contains(body, "38.207.164.191") {
		t.Fatalf("expected sing-box apt-hcloud node to avoid private DoH, got %q", body)
	}
}

func TestRouterClientSubscribeSingboxUserAgentUsesJSONProfile(t *testing.T) {
	userService := &fakeUserService{
		resolvedClientUserID: 10,
		subscribe: user.Subscribe{
			U:              11,
			D:              22,
			TransferEnable: 100,
			ExpiredAt:      int64Ptr(1234567890),
			UUID:           "user-uuid",
		},
		servers: []map[string]any{
			{
				"type":        "trojan",
				"name":        "Trojan-1",
				"host":        "trojan.example.com",
				"port":        int64(443),
				"network":     "tcp",
				"tls":         int64(1),
				"server_name": "trojan.example.com",
			},
		},
	}
	router := NewRouter(config.Config{AppName: "Forest"}, WithUserService(userService))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/subscribe?token=token-1", nil)
	req.Header.Set("User-Agent", "sing-box 1.12.1")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "application/json") {
		t.Fatalf("expected sing-box UA subscribe to return json, got %q with body %q", contentType, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "\"outbounds\"") || !strings.Contains(body, "\"Trojan-1\"") {
		t.Fatalf("expected sing-box json body, got %q", body)
	}
}

func TestRouterClientSubscribeLegacySingboxUserAgentUsesLegacyTemplate(t *testing.T) {
	userService := &fakeUserService{
		resolvedClientUserID: 10,
		subscribe: user.Subscribe{
			U:              11,
			D:              22,
			TransferEnable: 100,
			ExpiredAt:      int64Ptr(1234567890),
			UUID:           "user-uuid",
		},
		servers: []map[string]any{
			{
				"type":    "vmess",
				"name":    "VMess-1",
				"host":    "node.example.com",
				"port":    int64(443),
				"network": "ws",
				"tls":     int64(1),
				"tls_settings": map[string]any{
					"server_name": "node.example.com",
				},
				"network_settings": map[string]any{
					"path": "/ws",
				},
			},
		},
	}
	router := NewRouter(config.Config{AppName: "Forest"}, WithUserService(userService))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/subscribe?token=token-1", nil)
	req.Header.Set("User-Agent", "sing-box 1.11.9")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "application/json") {
		t.Fatalf("expected legacy sing-box subscribe to return json, got %q with body %q", contentType, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "\"tag\":\"direct\"") || !strings.Contains(body, "\"VMess-1\"") {
		t.Fatalf("expected legacy sing-box template body, got %q", body)
	}
}

func TestRouterClientSubscribeShadowrocketModuleEndpointReturnsDoHHostModule(t *testing.T) {
	userService := &fakeUserService{
		resolvedClientUserID: 10,
		subscribe:            user.Subscribe{UUID: "user-uuid"},
	}
	router := NewRouter(config.Config{AppName: "Forest"}, WithUserService(userService))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/subscribe?token=token-1&flag=shadowrocket-module", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "text/plain") {
		t.Fatalf("expected text/plain module response, got %q", contentType)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "#!name=Forest DoH Module") || !strings.Contains(body, "[Host]") {
		t.Fatalf("expected shadowrocket module header, got %q", body)
	}
	if strings.Contains(body, "38.207.164.191") || strings.Contains(body, "apt-hcloud.dev = server:") {
		t.Fatalf("shadowrocket module should not include private DoH host rules, got %q", body)
	}
	if strings.Contains(body, "dns-server") {
		t.Fatalf("module should not override global DNS server, got %q", body)
	}
}

func TestRouterClientSubscribeShadowrocketModuleToleratesFlagAppendedAfterQueryToken(t *testing.T) {
	userService := &fakeUserService{
		resolvedClientUserID: 10,
		subscribe:            user.Subscribe{UUID: "user-uuid"},
	}
	router := NewRouter(config.Config{AppName: "Forest"}, WithUserService(userService))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/subscribe?token=token-1?flag=shadowrocket-module", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected malformed module URL to still authenticate, got %d: %s", rec.Code, rec.Body.String())
	}
	if userService.lastClientToken != "token-1" {
		t.Fatalf("expected token to be recovered before stray flag, got %q", userService.lastClientToken)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "#!name=Forest DoH Module") {
		t.Fatalf("expected shadowrocket module body, got %q", body)
	}
	if strings.Contains(body, "38.207.164.191") || strings.Contains(body, "apt-hcloud.dev = server:") {
		t.Fatalf("shadowrocket module should not include private DoH, got %q", body)
	}
}

func TestRouterClientSubscribeShadowrocketEndpointUsesLegacyStatusLine(t *testing.T) {
	userService := &fakeUserService{
		resolvedClientUserID: 10,
		subscribe: user.Subscribe{
			U:              1024 * 1024 * 1024,
			D:              2 * 1024 * 1024 * 1024,
			TransferEnable: 10 * 1024 * 1024 * 1024,
			ExpiredAt:      int64Ptr(1735689600),
			UUID:           "user-uuid",
		},
		servers: []map[string]any{
			{
				"type":    "vmess",
				"name":    "VMess-1",
				"host":    "node.example.com",
				"port":    int64(443),
				"network": "ws",
				"tls":     int64(1),
				"tls_settings": map[string]any{
					"server_name": "node.example.com",
				},
				"network_settings": map[string]any{
					"path": "/ws",
					"headers": map[string]any{
						"Host": "node.example.com",
					},
				},
			},
		},
	}
	router := NewRouter(config.Config{AppName: "Forest"}, WithUserService(userService))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/subscribe?token=token-1&flag=shadowrocket", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rec.Body.String()))
	if err != nil {
		t.Fatalf("expected base64 shadowrocket body: %v", err)
	}
	body := string(decoded)
	if !strings.Contains(body, "STATUS=") {
		t.Fatalf("expected shadowrocket body to keep legacy status line, got %q", body)
	}
	if !strings.Contains(body, "Expires:2025-01-01") {
		t.Fatalf("expected shadowrocket body to include legacy expiry text, got %q", body)
	}
	if !strings.Contains(body, "remark=VMess-1") {
		t.Fatalf("expected shadowrocket body to keep legacy vmess format, got %q", body)
	}
}

func TestRouterClientSubscribeClashEndpointCanInjectInfoServers(t *testing.T) {
	userService := &fakeUserService{
		resolvedClientUserID: 10,
		subscribe: user.Subscribe{
			U:              1024,
			D:              2048,
			TransferEnable: 10 * 1024 * 1024 * 1024,
			ExpiredAt:      int64Ptr(1735689600),
			ResetDay:       int64Ptr(3),
			UUID:           "user-uuid",
		},
		servers: []map[string]any{
			{
				"type":    "vmess",
				"name":    "VMess-1",
				"host":    "node.example.com",
				"port":    int64(443),
				"network": "ws",
				"tls":     int64(1),
				"tls_settings": map[string]any{
					"server_name": "node.example.com",
				},
				"network_settings": map[string]any{
					"path": "/ws",
					"headers": map[string]any{
						"Host": "node.example.com",
					},
				},
			},
		},
	}
	router := NewRouter(config.Config{
		AppName:                "Forest",
		PublicDir:              "../public",
		ShowInfoToServerEnable: true,
	}, WithUserService(userService))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/client/subscribe?token=token-1&flag=clash", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "剩余流量：") {
		t.Fatalf("expected clash profile to inject remaining traffic server, got %q", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "套餐到期：2025-01-01") {
		t.Fatalf("expected clash profile to inject expiry server, got %q", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "距离下次重置剩余：3 天") {
		t.Fatalf("expected clash profile to inject reset day server, got %q", rec.Body.String())
	}
}

func TestRouterClientSubscribeCustomPathEndpoint(t *testing.T) {
	userService := &fakeUserService{
		resolvedClientUserID: 10,
		subscribe: user.Subscribe{
			UUID: "user-uuid",
		},
		servers: []map[string]any{},
	}
	router := NewRouter(config.Config{SubscribePath: "/forest-sub"}, WithUserService(userService))

	req := httptest.NewRequest(http.MethodGet, "/forest-sub?token=token-1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected custom subscribe path to work, got %d: %s", rec.Code, rec.Body.String())
	}

	defaultReq := httptest.NewRequest(http.MethodGet, "/api/v1/client/subscribe?token=token-1", nil)
	defaultRec := httptest.NewRecorder()
	router.ServeHTTP(defaultRec, defaultReq)
	if defaultRec.Code != http.StatusOK {
		t.Fatalf("expected default subscribe path to remain compatible, got %d: %s", defaultRec.Code, defaultRec.Body.String())
	}
}

func TestRouterClientSubscribeCustomPathEndpointAllowsTrailingSlash(t *testing.T) {
	userService := &fakeUserService{
		resolvedClientUserID: 10,
		subscribe: user.Subscribe{
			UUID: "user-uuid",
		},
		servers: []map[string]any{},
	}
	router := NewRouter(config.Config{SubscribePath: "/forest-sub/"}, WithUserService(userService))

	req := httptest.NewRequest(http.MethodGet, "/forest-sub/?token=token-1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected trailing slash custom subscribe path to work, got %d: %s", rec.Code, rec.Body.String())
	}
	if userService.lastClientToken != "token-1" {
		t.Fatalf("expected query token to be preserved, got %q", userService.lastClientToken)
	}
}

func TestRouterClientSubscribeCustomPathTokenSegment(t *testing.T) {
	userService := &fakeUserService{
		resolvedClientUserID: 10,
		subscribe: user.Subscribe{
			UUID: "user-uuid",
		},
		servers: []map[string]any{},
	}
	router := NewRouter(config.Config{SubscribePath: "/forest-sub", SubscribeTokenInPath: true}, WithUserService(userService))

	req := httptest.NewRequest(http.MethodGet, "/forest-sub/token-1?flag=clash", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected custom subscribe token segment to work, got %d: %s", rec.Code, rec.Body.String())
	}
	if userService.lastClientToken != "token-1" {
		t.Fatalf("expected token from path segment, got %q", userService.lastClientToken)
	}
}

func TestRouterClientSubscribeCustomPathTokenSegmentShadowrocketModule(t *testing.T) {
	userService := &fakeUserService{
		resolvedClientUserID: 10,
		subscribe: user.Subscribe{
			UUID: "user-uuid",
		},
		servers: []map[string]any{},
	}
	router := NewRouter(config.Config{AppName: "Forest", SubscribePath: "/forest", SubscribeTokenInPath: true}, WithUserService(userService))

	req := httptest.NewRequest(http.MethodGet, "/forest/token-1?flag=shadowrocket-module", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected custom path shadowrocket module to work, got %d: %s", rec.Code, rec.Body.String())
	}
	if userService.lastClientToken != "token-1" {
		t.Fatalf("expected token from path segment, got %q", userService.lastClientToken)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "#!name=Forest DoH Module") {
		t.Fatalf("expected shadowrocket module body, got %q", body)
	}
	if strings.Contains(body, "38.207.164.191") || strings.Contains(body, "apt-hcloud.dev = server:") {
		t.Fatalf("shadowrocket module should not include private DoH, got %q", body)
	}
}

func TestBuildV2ServerConfigJuicityExternalProtocol(t *testing.T) {
	server := nodeapi.ServerRecord{
		ID:       11,
		NodeType: "v2node",
		Fields: map[string]any{
			"listen_ip":          "0.0.0.0",
			"server_port":        int64(443),
			"protocol":           "juicity",
			"tls":                int64(1),
			"tls_settings":       map[string]any{"server_name": "j.example.com", "certificate_file": "/etc/ssl/j.crt"},
			"congestion_control": "bbr",
		},
	}

	payload := buildV2ServerConfig(config.Config{}, server, nil)

	if payload["protocol"] != "juicity" || payload["server_port"] != int64(443) {
		t.Fatalf("expected common juicity fields, got %#v", payload)
	}
	if payload["external_protocol"] != true {
		t.Fatalf("expected external_protocol=true, got %#v", payload["external_protocol"])
	}
	if payload["traffic_mode"] != "observer" || payload["password_mode"] != "uuid" {
		t.Fatalf("unexpected external modes: traffic=%#v password=%#v", payload["traffic_mode"], payload["password_mode"])
	}
	if payload["congestion_control"] != "bbr" {
		t.Fatalf("expected congestion_control preserved, got %#v", payload["congestion_control"])
	}
	tlsSettings, ok := payload["tls_settings"].(map[string]any)
	if !ok || tlsSettings["server_name"] != "j.example.com" {
		t.Fatalf("expected tls settings preserved, got %#v", payload["tls_settings"])
	}
}

func TestBuildV2ServerConfigMieruExternalProtocol(t *testing.T) {
	server := nodeapi.ServerRecord{
		ID:       12,
		NodeType: "v2node",
		Fields: map[string]any{
			"listen_ip":        "0.0.0.0",
			"server_port":      int64(2999),
			"protocol":         "mieru",
			"network_settings": map[string]any{"transport": "UDP", "mtu": int64(1280), "multiplexing": "MULTIPLEXING_LOW"},
		},
	}

	payload := buildV2ServerConfig(config.Config{}, server, nil)

	if payload["protocol"] != "mieru" || payload["server_port"] != int64(2999) {
		t.Fatalf("expected common mieru fields, got %#v", payload)
	}
	if payload["external_protocol"] != true {
		t.Fatalf("expected external_protocol=true, got %#v", payload["external_protocol"])
	}
	if payload["traffic_mode"] != "metrics" || payload["password_mode"] != "uuid" {
		t.Fatalf("unexpected external modes: traffic=%#v password=%#v", payload["traffic_mode"], payload["password_mode"])
	}
	if payload["transport"] != "UDP" || payload["mtu"] != int64(1280) || payload["multiplexing"] != "MULTIPLEXING_LOW" {
		t.Fatalf("unexpected mieru settings: transport=%#v mtu=%#v multiplexing=%#v", payload["transport"], payload["mtu"], payload["multiplexing"])
	}
}

func TestBuildV2ServerConfigMieruExternalProtocolDefaults(t *testing.T) {
	server := nodeapi.ServerRecord{
		ID:       13,
		NodeType: "v2node",
		Fields: map[string]any{
			"server_port": int64(2999),
			"protocol":    "mieru",
		},
	}

	payload := buildV2ServerConfig(config.Config{}, server, nil)

	if payload["transport"] != "TCP" || payload["mtu"] != int64(1400) {
		t.Fatalf("expected mieru defaults, got transport=%#v mtu=%#v", payload["transport"], payload["mtu"])
	}
}

func TestRouterServerV2ConfigEndpoint(t *testing.T) {
	t.Setenv("SERVER_PUSH_INTERVAL", "90")
	t.Setenv("SERVER_PULL_INTERVAL", "45")
	t.Setenv("SERVER_NODE_REPORT_MIN_TRAFFIC", "2048")
	t.Setenv("SERVER_DEVICE_ONLINE_MIN_TRAFFIC", "4096")
	t.Setenv("SUBSCRIBE_GUARD_SENSITIVE_ENABLE", "1")
	t.Setenv("SUBSCRIBE_GUARD_SENSITIVE_RULES", "suffix:example.com")
	t.Setenv("SUBSCRIBE_GUARD_SENSITIVE_INTERVAL", "30")
	t.Setenv("SUBSCRIBE_GUARD_SENSITIVE_LOG_IP", "1")

	nodeService := &fakeNodeService{
		server: nodeapi.ServerRecord{
			ID:       9,
			NodeType: "v2node",
			RouteIDs: []int64{3},
			Fields: map[string]any{
				"listen_ip":           "0.0.0.0",
				"send_through":        "198.51.100.7",
				"server_port":         int64(443),
				"network":             "ws",
				"network_settings":    map[string]any{"path": "/ws"},
				"protocol":            "vmess",
				"tls":                 int64(1),
				"tls_settings":        map[string]any{"server_name": "node.example.com"},
				"encryption":          "none",
				"encryption_settings": map[string]any{},
				"flow":                "xtls-rprx-vision",
				"cipher":              "2022-blake3-aes-128-gcm",
				"congestion_control":  "bbr",
				"zero_rtt_handshake":  int64(1),
				"up_mbps":             int64(0),
				"down_mbps":           int64(0),
				"obfs":                "salamander",
				"obfs_password":       "secret",
				"padding_scheme":      []any{"stop=8"},
				"created_at":          int64(1700000000),
			},
		},
		routes: []map[string]any{
			{"id": int64(3), "match": []any{"geosite:cn"}, "action": "direct"},
		},
	}
	router := NewRouter(config.Load(), WithNodeService(nodeService))

	req := httptest.NewRequest(http.MethodGet, "/api/v2/server/config?token=&node_id=9", nil)
	req.URL.RawQuery = "token=" + "secret" + "&node_id=9"
	rec := httptest.NewRecorder()

	cfg := config.Load()
	cfg.ServerToken = "secret"
	router = NewRouter(cfg, WithNodeService(nodeService))
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("ETag") == "" {
		t.Fatal("expected etag header")
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected json body: %v", err)
	}
	if payload["listen_ip"] != "0.0.0.0" || payload["protocol"] != "vmess" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
	if payload["send_through"] != "198.51.100.7" {
		t.Fatalf("expected send_through to be preserved, got %#v", payload["send_through"])
	}
	if payload["ignore_client_bandwidth"] != true {
		t.Fatalf("expected ignore_client_bandwidth=true, got %#v", payload["ignore_client_bandwidth"])
	}
	baseConfig, ok := payload["base_config"].(map[string]any)
	if !ok {
		t.Fatalf("expected base_config object, got %#v", payload["base_config"])
	}
	if baseConfig["push_interval"] != float64(90) || baseConfig["node_report_min_traffic"] != float64(2048) || baseConfig["device_online_min_traffic"] != float64(4096) {
		t.Fatalf("unexpected base config: %#v", baseConfig)
	}
	sensitiveAudit, ok := payload["sensitive_audit"].(map[string]any)
	if !ok {
		t.Fatalf("expected sensitive_audit object, got %#v", payload["sensitive_audit"])
	}
	if sensitiveAudit["enable"] != false || sensitiveAudit["report_interval"] != float64(60) || sensitiveAudit["log_client_ip"] != false {
		t.Fatalf("unexpected sensitive audit: %#v", sensitiveAudit)
	}
	rules, ok := sensitiveAudit["rules"].([]any)
	if !ok || len(rules) != 0 {
		t.Fatalf("unexpected sensitive audit rules: %#v", sensitiveAudit["rules"])
	}
}

func TestRouterServerV2ConfigEndpointKeepsPrivateKeys(t *testing.T) {
	nodeService := &fakeNodeService{
		server: nodeapi.ServerRecord{
			ID:       9,
			NodeType: "v2node",
			Fields: map[string]any{
				"listen_ip":           "0.0.0.0",
				"server_port":         int64(443),
				"network":             "tcp",
				"protocol":            "vless",
				"tls":                 int64(2),
				"tls_settings":        map[string]any{"private_key": "tls-private", "public_key": "tls-public"},
				"encryption":          "none",
				"encryption_settings": map[string]any{"private_key": "enc-private", "public_key": "enc-public"},
			},
		},
	}
	cfg := config.Load()
	cfg.ServerToken = "secret"
	router := NewRouter(cfg, WithNodeService(nodeService))

	req := httptest.NewRequest(http.MethodGet, "/api/v2/server/config?token=secret&node_id=9", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected json body: %v", err)
	}
	tlsSettings, ok := payload["tls_settings"].(map[string]any)
	if !ok || tlsSettings["private_key"] != "tls-private" {
		t.Fatalf("expected tls private key kept, got %#v", payload["tls_settings"])
	}
	encryptionSettings, ok := payload["encryption_settings"].(map[string]any)
	if !ok || encryptionSettings["private_key"] != "enc-private" {
		t.Fatalf("expected encryption private key kept, got %#v", payload["encryption_settings"])
	}
}

func TestRouterServerV2ConfigEndpointStringifiesTLSServerPort(t *testing.T) {
	nodeService := &fakeNodeService{
		server: nodeapi.ServerRecord{
			ID:       9,
			NodeType: "v2node",
			Fields: map[string]any{
				"listen_ip":   "0.0.0.0",
				"server_port": int64(23130),
				"network":     "tcp",
				"protocol":    "anytls",
				"tls":         int64(1),
				"tls_settings": map[string]any{
					"server_name": "buylite.music.apple.com",
					"server_port": int64(443),
					"xver":        int64(0),
				},
			},
		},
	}
	cfg := config.Load()
	cfg.ServerToken = "secret"
	router := NewRouter(cfg, WithNodeService(nodeService))

	req := httptest.NewRequest(http.MethodGet, "/api/v2/server/config?token=secret&node_id=9&node_type=v2node", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected json body: %v", err)
	}
	tlsSettings, ok := payload["tls_settings"].(map[string]any)
	if !ok {
		t.Fatalf("expected tls_settings object, got %#v", payload["tls_settings"])
	}
	if tlsSettings["server_port"] != "443" {
		t.Fatalf("expected tls_settings.server_port string, got %#v", tlsSettings["server_port"])
	}
	if tlsSettings["xver"] != "0" {
		t.Fatalf("expected tls_settings.xver string, got %#v", tlsSettings["xver"])
	}
	if payload["server_port"] != float64(23130) {
		t.Fatalf("expected top-level server_port to stay numeric, got %#v", payload["server_port"])
	}
}

func TestRouterServerV2ConfigEndpointMissingTokenKeepsLegacyFailureShape(t *testing.T) {
	router := NewRouter(config.Config{AppName: "forest-go"}, WithNodeService(&fakeNodeService{}))

	req := httptest.NewRequest(http.MethodGet, "/api/v2/server/config?node_id=9", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected json body: %v", err)
	}
	if payload["status"] != "fail" || payload["message"] != "token is null" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestRouterServerV2ConfigEndpointServerMissingKeepsLegacyFailureShape(t *testing.T) {
	nodeService := &fakeNodeService{err: errors.New("server is not exist")}
	cfg := config.Load()
	cfg.ServerToken = "secret"
	router := NewRouter(cfg, WithNodeService(nodeService))

	req := httptest.NewRequest(http.MethodGet, "/api/v2/server/config?token=secret&node_id=9", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected json body: %v", err)
	}
	if payload["status"] != "fail" || payload["message"] != "server is not exist" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}
