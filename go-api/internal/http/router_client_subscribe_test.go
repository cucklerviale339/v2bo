package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	usersvc "forest/go-api/internal/user"
)

func TestBuildGeneralSubscribePayloadInfersLegacyV2nodeProtocol(t *testing.T) {
	payload := buildGeneralSubscribePayload("user-uuid", []map[string]any{
		{
			"type":     "v2node",
			"protocol": nil,
			"name":     "Legacy-V2node",
			"host":     "node.example.com",
			"port":     int64(443),
			"network":  "ws",
			"tls":      int64(1),
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
	})

	if strings.TrimSpace(payload) == "" {
		t.Fatal("expected legacy v2node payload to stay non-empty")
	}

	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if !strings.Contains(string(decoded), "vmess://") {
		t.Fatalf("expected vmess uri in payload, got %q", string(decoded))
	}
}

func TestBuildLoonPayloadUsesDedicatedPlainTextFormat(t *testing.T) {
	payload := buildLoonPayload("user-uuid", []map[string]any{
		{
			"type":    "vmess",
			"name":    "loon-vmess",
			"host":    "node.example.com",
			"port":    int64(443),
			"network": "ws",
			"tls":     int64(1),
			"networkSettings": map[string]any{
				"path": "/ws",
				"headers": map[string]any{
					"Host": "cdn.example.com",
				},
			},
		},
	})

	if !strings.Contains(payload, "loon-vmess=vmess,node.example.com,443") {
		t.Fatalf("expected loon vmess line, got %q", payload)
	}
	if strings.Contains(payload, "vmess://") {
		t.Fatalf("expected loon plain text format, got generic uri payload %q", payload)
	}
}

func TestBuildLoonPayloadIncludesAnyTLS(t *testing.T) {
	payload := buildLoonPayload("user-uuid", []map[string]any{
		{
			"type":         "anytls",
			"name":         "loon-anytls",
			"host":         "node.example.com",
			"port":         int64(443),
			"insecure":     true,
			"server_name":  "sni.example.com",
			"tls_settings": map[string]any{"allow_insecure": true},
		},
	})

	want := "loon-anytls=AnyTLS,node.example.com,443,user-uuid,skip-cert-verify=true,sni=sni.example.com,udp=true,block-quic=false"
	if !strings.Contains(payload, want) {
		t.Fatalf("expected loon anytls line, got %q", payload)
	}
}

func TestBuildQuantumultXPayloadUsesDedicatedBase64Format(t *testing.T) {
	payload := buildQuantumultXPayload("user-uuid", []map[string]any{
		{
			"type":    "vmess",
			"name":    "qx-vmess",
			"host":    "node.example.com",
			"port":    int64(443),
			"network": "ws",
			"tls":     int64(1),
			"networkSettings": map[string]any{
				"path": "/ws",
				"headers": map[string]any{
					"Host": "cdn.example.com",
				},
			},
		},
	})

	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode quantumult x payload: %v", err)
	}
	body := string(decoded)
	if !strings.Contains(body, "vmess=node.example.com:443") {
		t.Fatalf("expected quantumult x vmess line, got %q", body)
	}
	if strings.Contains(body, "vmess://") {
		t.Fatalf("expected quantumult x line format, got generic uri payload %q", body)
	}
}

func TestBuildQuantumultXPayloadIncludesAnyTLS(t *testing.T) {
	payload := buildQuantumultXPayload("user-uuid", []map[string]any{
		{
			"type":         "anytls",
			"name":         "qx-anytls",
			"host":         "node.example.com",
			"port":         int64(443),
			"insecure":     true,
			"server_name":  "sni.example.com",
			"tls_settings": map[string]any{"allow_insecure": true},
		},
	})

	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode quantumult x anytls payload: %v", err)
	}
	want := "anytls=node.example.com:443,password=user-uuid,over-tls=true,tls-host=sni.example.com,tls-verification=false,udp-relay=true,tag=qx-anytls"
	if !strings.Contains(string(decoded), want) {
		t.Fatalf("expected quantumult x anytls line, got %q", string(decoded))
	}
}

func TestBuildSurfboardAnyTLSUsesPositionalPassword(t *testing.T) {
	line, ok := buildSurfboardProxyLine("user-uuid", map[string]any{
		"type":         "anytls",
		"name":         "surfboard-anytls",
		"host":         "node.example.com",
		"port":         int64(443),
		"insecure":     true,
		"server_name":  "sni.example.com",
		"tls_settings": map[string]any{"allow_insecure": true},
	})
	if !ok {
		t.Fatal("expected surfboard anytls node to be supported")
	}

	want := "surfboard-anytls=anytls,node.example.com,443,user-uuid,skip-cert-verify=true,sni=sni.example.com,udp-relay=true"
	if !strings.Contains(line, want) {
		t.Fatalf("expected surfboard anytls line, got %q", line)
	}
	if strings.Contains(line, "password=user-uuid") {
		t.Fatalf("expected positional surfboard password, got %q", line)
	}
}

func TestBuildShadowsocksSIP008Profile(t *testing.T) {
	payload, err := buildShadowsocksSIP008Profile(usersvc.Subscribe{
		UUID:           "user-uuid",
		U:              1024,
		D:              2048,
		TransferEnable: 8192,
	}, []map[string]any{
		{
			"id":     int64(7),
			"type":   "shadowsocks",
			"name":   "ss-node",
			"host":   "ss.example.com",
			"port":   int64(8388),
			"cipher": "aes-256-gcm",
		},
	})
	if err != nil {
		t.Fatalf("build sip008 profile: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("decode sip008 profile: %v", err)
	}
	servers := decoded["servers"].([]any)
	if len(servers) != 1 {
		t.Fatalf("expected one server, got %#v", servers)
	}
	server := servers[0].(map[string]any)
	if server["remarks"] != "ss-node" || server["password"] != "user-uuid" {
		t.Fatalf("unexpected sip008 server: %#v", server)
	}
}
