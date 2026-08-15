package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"forest/go-api/internal/subscribelink"
	usersvc "forest/go-api/internal/user"
)

func TestExtraTrojanRendersOwnCredentialAcrossStructuredFormats(t *testing.T) {
	const (
		raw        = "trojan://8E28E6FF-2F00-14C1-FD08-D6D91AFF8A37@58.247.187.151:20003?allowInsecure=1&peer=mpvideo.qpic.cn#Hong%20Kong%20%7C%2001"
		credential = "8E28E6FF-2F00-14C1-FD08-D6D91AFF8A37"
	)
	node, err := subscribelink.Parse(raw)
	if err != nil {
		t.Fatalf("parse extra Trojan: %v", err)
	}

	clash, ok := buildClashStandardProxy("subscriber-uuid", node)
	if !ok {
		t.Fatal("extra Trojan was omitted from Clash output")
	}
	assertExtraTrojanProxy(t, clash, "name", "server", "port", "password")
	if got := clash["sni"]; got != "mpvideo.qpic.cn" {
		t.Fatalf("Clash SNI = %#v", got)
	}
	if got := clash["skip-cert-verify"]; got != true {
		t.Fatalf("Clash skip-cert-verify = %#v", got)
	}

	singBox, ok := buildSingBoxOutbound("subscriber-uuid", node)
	if !ok {
		t.Fatal("extra Trojan was omitted from sing-box output")
	}
	assertExtraTrojanProxy(t, singBox, "tag", "server", "server_port", "password")
	tlsSettings, ok := singBox["tls"].(map[string]any)
	if !ok || tlsSettings["server_name"] != "mpvideo.qpic.cn" || tlsSettings["insecure"] != true {
		t.Fatalf("unexpected sing-box TLS settings: %#v", singBox["tls"])
	}

	surge, ok := buildSurgeProxyLine("subscriber-uuid", node)
	if !ok {
		t.Fatal("extra Trojan was omitted from Surge output")
	}
	for _, part := range []string{
		"Hong Kong | 01=trojan",
		"58.247.187.151",
		"20003",
		"password=" + credential,
		"sni=mpvideo.qpic.cn",
		"skip-cert-verify=true",
	} {
		if !strings.Contains(surge, part) {
			t.Fatalf("Surge output %q does not contain %q", surge, part)
		}
	}
	if strings.Contains(surge, "subscriber-uuid") {
		t.Fatalf("Surge output replaced standalone credential: %q", surge)
	}
}

func TestNormalTrojanStillUsesSubscriberCredential(t *testing.T) {
	node := map[string]any{
		"type":        "trojan",
		"name":        "Managed",
		"host":        "managed.example.com",
		"port":        int64(443),
		"server_name": "managed.example.com",
	}
	proxy, ok := buildClashStandardProxy("subscriber-uuid", node)
	if !ok || proxy["password"] != "subscriber-uuid" {
		t.Fatalf("managed Trojan credential behavior changed: %#v", proxy)
	}
}

func TestExtraTrojanRawAndShadowrocketKeepConfiguredLink(t *testing.T) {
	const raw = "trojan://fixed-secret@58.247.187.151:20003?allowInsecure=1&peer=mpvideo.qpic.cn#Extra"
	node, err := subscribelink.Parse(raw)
	if err != nil {
		t.Fatalf("parse extra Trojan: %v", err)
	}

	general := buildGeneralSubscribePayload("subscriber-uuid", []map[string]any{node})
	decoded, err := base64.StdEncoding.DecodeString(general)
	if err != nil {
		t.Fatalf("decode general payload: %v", err)
	}
	if got := strings.TrimSpace(string(decoded)); got != raw {
		t.Fatalf("general extra link = %q", got)
	}

	shadowrocket := buildShadowrocketPayload(usersvc.Subscribe{UUID: "subscriber-uuid"}, []map[string]any{node})
	decoded, err = base64.StdEncoding.DecodeString(shadowrocket)
	if err != nil {
		t.Fatalf("decode Shadowrocket payload: %v", err)
	}
	if !strings.Contains(string(decoded), raw+"\r\n") || strings.Contains(string(decoded), "subscriber-uuid@58.247.187.151") {
		t.Fatalf("Shadowrocket extra link changed: %q", string(decoded))
	}
}

func TestExtraAnyTLSSurfboardKeepsConfiguredCredential(t *testing.T) {
	const raw = "anytls://fixed-secret@anytls.example.com:443?sni=www.example.com#Extra"
	node, err := subscribelink.Parse(raw)
	if err != nil {
		t.Fatalf("parse extra AnyTLS: %v", err)
	}

	line, ok := buildSurfboardProxyLine("subscriber-uuid", node)
	if !ok || !strings.Contains(line, ",fixed-secret,") {
		t.Fatalf("Surfboard AnyTLS did not keep configured credential: %q", line)
	}
	if strings.Contains(line, "subscriber-uuid") {
		t.Fatalf("Surfboard AnyTLS used subscriber credential: %q", line)
	}
}

func TestExtraProtocolsKeepConfiguredCredentialsInClashAndSingBox(t *testing.T) {
	vmessURI := "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(`{"v":"2","ps":"VMess","add":"vmess.example.com","port":"443","id":"11111111-1111-1111-1111-111111111111","net":"ws","path":"/ws","host":"cdn.example.com","tls":"tls","sni":"cdn.example.com"}`))
	shadowsocksURI := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:ss-secret")) + "@ss.example.com:8388#SS"
	tests := []struct {
		name        string
		raw         string
		credentials []string
	}{
		{name: "VMess", raw: vmessURI, credentials: []string{"11111111-1111-1111-1111-111111111111"}},
		{name: "Shadowsocks", raw: shadowsocksURI, credentials: []string{"ss-secret"}},
		{name: "VLESS", raw: "vless://22222222-2222-2222-2222-222222222222@vless.example.com:443?security=tls&type=ws&host=cdn.example.com&path=%2Fws#VLESS", credentials: []string{"22222222-2222-2222-2222-222222222222"}},
		{name: "Trojan", raw: "trojan://trojan-secret@trojan.example.com:443?sni=cdn.example.com#Trojan", credentials: []string{"trojan-secret"}},
		{name: "Hysteria2", raw: "hysteria2://hy2-secret@hy2.example.com:443?sni=cdn.example.com&insecure=1#HY2", credentials: []string{"hy2-secret"}},
		{name: "AnyTLS", raw: "anytls://anytls-secret@anytls.example.com:443?sni=cdn.example.com#AnyTLS", credentials: []string{"anytls-secret"}},
		{name: "TUIC", raw: "tuic://33333333-3333-3333-3333-333333333333:tuic-secret@tuic.example.com:443?sni=cdn.example.com#TUIC", credentials: []string{"33333333-3333-3333-3333-333333333333", "tuic-secret"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			node, err := subscribelink.Parse(test.raw)
			if err != nil {
				t.Fatalf("parse extra node: %v", err)
			}

			clash, ok := buildClashStandardProxy("subscriber-uuid", node)
			if !ok {
				t.Fatal("extra node was omitted from Clash output")
			}
			assertExtraCredentialsInJSON(t, clash, test.credentials)

			singBox, ok := buildSingBoxOutbound("subscriber-uuid", node)
			if !ok {
				t.Fatal("extra node was omitted from sing-box output")
			}
			assertExtraCredentialsInJSON(t, singBox, test.credentials)
		})
	}
}

func assertExtraCredentialsInJSON(t *testing.T, value any, credentials []string) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal proxy: %v", err)
	}
	serialized := string(raw)
	if strings.Contains(serialized, "subscriber-uuid") {
		t.Fatalf("standalone credential was replaced: %s", serialized)
	}
	for _, credential := range credentials {
		if !strings.Contains(serialized, credential) {
			t.Fatalf("proxy output does not contain credential %q: %s", credential, serialized)
		}
	}
}

func assertExtraTrojanProxy(t *testing.T, proxy map[string]any, nameKey, hostKey, portKey, credentialKey string) {
	t.Helper()
	if got := proxy[nameKey]; got != "Hong Kong | 01" {
		t.Fatalf("%s = %#v", nameKey, got)
	}
	if got := proxy[hostKey]; got != "58.247.187.151" {
		t.Fatalf("%s = %#v", hostKey, got)
	}
	if got := proxy[portKey]; got != int64(20003) {
		t.Fatalf("%s = %#v", portKey, got)
	}
	if got := proxy[credentialKey]; got != "8E28E6FF-2F00-14C1-FD08-D6D91AFF8A37" {
		t.Fatalf("%s = %#v", credentialKey, got)
	}
}
