package subscribeguard

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTrustedProxyBoundary(t *testing.T) {
	for _, test := range []struct {
		name, peer, forwarded, expected string
		proxies                         []string
	}{
		{"direct spoof", "198.51.100.8:9000", "203.0.113.2", "198.51.100.8", nil},
		{"default local proxy", "127.0.0.1:8000", "203.0.113.2", "203.0.113.2", nil},
		{"saved empty proxy list", "127.0.0.1:8000", "203.0.113.2", "203.0.113.2", []string{}},
		{"default ipv6 proxy", "[::1]:8000", "2001:db8::8", "2001:db8::8", nil},
		{"default mapped proxy", "[::ffff:127.0.0.1]:8000", "::ffff:203.0.113.2", "203.0.113.2", nil},
		{"default untrusted middle", "127.0.0.1:8000", "192.0.2.8, 198.51.100.4", "198.51.100.4", nil},
		{"private peer is not trusted by default", "10.0.0.8:8000", "192.0.2.8", "10.0.0.8", nil},
		{"explicit proxy list replaces default", "127.0.0.1:8000", "192.0.2.8", "127.0.0.1", []string{"10.0.0.0/24"}},
		{"trusted single hop", "127.0.0.1:8000", "203.0.113.2", "203.0.113.2", []string{"127.0.0.1/32"}},
		{"untrusted middle hop", "127.0.0.1:8000", "192.0.2.8, 198.51.100.4", "198.51.100.4", []string{"127.0.0.1/32"}},
		{"trusted multiple hops", "127.0.0.1:8000", "192.0.2.8, 10.0.0.8", "192.0.2.8", []string{"127.0.0.1/32", "10.0.0.0/24"}},
		{"invalid chain", "127.0.0.1:8000", "not-an-ip", "127.0.0.1", []string{"127.0.0.1/32"}},
		{"mapped ipv6", "[::ffff:198.51.100.8]:4000", "203.0.113.2", "198.51.100.8", nil},
		{"ipv6 proxy", "[::1]:4000", "2001:db8::8", "2001:db8::8", []string{"::1/128"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("GET", "/", nil)
			request.RemoteAddr = test.peer
			request.Header.Set("X-Forwarded-For", test.forwarded)
			request.Header.Set("CF-Connecting-IP", "1.1.1.1")
			if got := ClientIP(request, test.proxies); got != test.expected {
				t.Fatalf("got %q want %q", got, test.expected)
			}
		})
	}
}

func TestClientIPForwardingHeaders(t *testing.T) {
	for _, test := range []struct {
		name, peer, realIP, expected string
		forwarded                    []string
	}{
		{name: "local real IP", peer: "127.0.0.1:8000", realIP: "203.0.113.2", expected: "203.0.113.2"},
		{name: "IPv6 real IP", peer: "[::1]:8000", realIP: "2001:db8::8", expected: "2001:db8::8"},
		{name: "direct real IP spoof", peer: "198.51.100.8:8000", realIP: "203.0.113.2", expected: "198.51.100.8"},
		{name: "forwarded takes precedence", peer: "127.0.0.1:8000", realIP: "192.0.2.1", forwarded: []string{"203.0.113.2"}, expected: "203.0.113.2"},
		{name: "multiple header lines", peer: "127.0.0.1:8000", forwarded: []string{"192.0.2.1", "203.0.113.2"}, expected: "203.0.113.2"},
		{name: "invalid forwarded does not use real IP", peer: "127.0.0.1:8000", realIP: "203.0.113.2", forwarded: []string{"invalid"}, expected: "127.0.0.1"},
		{name: "empty forwarded does not use real IP", peer: "127.0.0.1:8000", realIP: "203.0.113.2", forwarded: []string{""}, expected: "127.0.0.1"},
		{name: "long chain", peer: "127.0.0.1:8000", forwarded: []string{strings.Repeat("203.0.113.2,", 32) + "203.0.113.2"}, expected: "127.0.0.1"},
		{name: "invalid real IP", peer: "127.0.0.1:8000", realIP: "invalid", expected: "127.0.0.1"},
		{name: "no forwarding headers", peer: "127.0.0.1:8000", expected: "127.0.0.1"},
		{name: "invalid socket peer", peer: "invalid", realIP: "203.0.113.2", expected: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("GET", "/", nil)
			request.RemoteAddr = test.peer
			for _, value := range test.forwarded {
				request.Header.Add("X-Forwarded-For", value)
			}
			if test.realIP != "" {
				request.Header.Set("X-Real-IP", test.realIP)
			}
			request.Header.Set("CF-Connecting-IP", "1.1.1.1")
			request.Header.Set("True-Client-IP", "1.1.1.1")
			if got := ClientIP(request, nil); got != test.expected {
				t.Fatalf("got %q want %q", got, test.expected)
			}
		})
	}
}

func TestRulesPrecedenceExpiryAndTokenPrivacy(t *testing.T) {
	policy := DefaultPolicy()
	policy.Mode = "observe"
	policy.BlockCrawlerUA = true
	policy.Rules = []Rule{
		{Kind: "ip_allow", Value: "192.0.2.0/24"},
		{Kind: "ip_block", Value: "192.0.2.4"},
		{Kind: "ua_allow", Value: "clash"},
		{Kind: "ua_block", Value: "clash"},
		{Kind: "token_block", Token: "private-subscription-token"},
		{Kind: "ip_block", Value: "198.51.100.8", ExpiresAt: 100},
	}
	if err := policy.Validate("secret-key"); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(policy)
	if strings.Contains(string(raw), "private-subscription-token") {
		t.Fatal("raw token persisted")
	}
	if Fingerprint("secret-key", "private-subscription-token") == Fingerprint("different-key", "private-subscription-token") {
		t.Fatal("fingerprint not keyed")
	}
	now := time.Unix(200, 0)
	if got := policy.Reason("192.0.2.4", "", "curl", now); got != "" {
		t.Fatalf("IP allow failed: %s", got)
	}
	if got := policy.Reason("192.0.2.4", Fingerprint("secret-key", "private-subscription-token"), "clash", now); got != "token" {
		t.Fatalf("IP allow bypassed token block: %s", got)
	}
	if got := policy.Reason("198.51.100.8", "", "Clash curl", now); got != "" {
		t.Fatalf("expiry/UA allow failed: %s", got)
	}
	if got := policy.Reason("198.51.100.8", "", "curl", now); got != "crawler_ua" {
		t.Fatalf("crawler not recognized: %s", got)
	}
}

func TestRejectUnsafeOrInvalidPolicy(t *testing.T) {
	for _, change := range []func(*Policy){
		func(policy *Policy) { policy.Mode = "unknown" },
		func(policy *Policy) { policy.TrustedProxies = []string{"0.0.0.0/0"} },
		func(policy *Policy) { policy.Rules = []Rule{{Kind: "ip_allow", Value: "::/0"}} },
		func(policy *Policy) { policy.Rules = []Rule{{Kind: "token_block", Value: "raw-token"}} },
		func(policy *Policy) { policy.Rules = []Rule{{Kind: "ua_block", Value: " "}} },
		func(policy *Policy) { policy.Rules = []Rule{{Kind: "user_block", Value: "0"}} },
		func(policy *Policy) {
			policy.Rules = []Rule{{Kind: "ip_block", Value: "192.0.2.1"}, {Kind: "ip_block", Value: "192.0.2.1"}}
		},
		func(policy *Policy) { policy.IPLimit = -1 },
	} {
		policy := DefaultPolicy()
		change(&policy)
		if err := policy.Validate("key"); err == nil {
			t.Fatalf("accepted invalid policy: %#v", policy)
		}
	}
}

func TestRequestedUASemanticsAndRawTokenBlacklist(t *testing.T) {
	policy := DefaultPolicy()
	policy.BlockCrawlerUA = true
	policy.BlockEmptyUA = true
	policy.TokenBlacklist = []string{"Exact-Case-Token"}
	policy.Rules = []Rule{{Kind: "ua_allow", Value: "TRUSTED"}, {Kind: "ua_block", Value: "X"}}
	if err := policy.Validate("key"); err != nil {
		t.Fatal(err)
	}
	for _, agent := range []string{"curl/8", "WGET", "Python-requests", "aiohttp", "urllib/3", "Go-http-client/1.1", "Java/17", "okhttp", "HTTPCLIENT", "Scrapy", "Googlebot/2.1"} {
		if !IsCrawlerUA(agent) || policy.Reason("", "", agent, time.Now()) == "" {
			t.Fatalf("not detected: %s", agent)
		}
		if policy.Reason("", "", "Trusted "+agent, time.Now()) != "" {
			t.Fatalf("whitelist did not skip UA: %s", agent)
		}
	}
	if policy.Reason("", "", "prefix", time.Now()) != "ua" || policy.Reason("", "", "", time.Now()) != "empty_ua" {
		t.Fatal("UA semantics changed")
	}
	if policy.Reason("", Fingerprint("key", "Exact-Case-Token"), "Trusted", time.Now()) != "token" {
		t.Fatal("raw token not blocked")
	}
	if policy.Reason("", Fingerprint("key", "exact-case-token"), "Trusted", time.Now()) != "" {
		t.Fatal("token match ignored case")
	}
	policy.BlockCrawlerUA = false
	if !IsCrawlerUA("curl") || policy.Reason("", "", "curl", time.Now()) != "" {
		t.Fatal("crawler switch does not preserve detection")
	}
}

func TestCrawlerDetectionDoesNotFlagCommonSubscriptionClients(t *testing.T) {
	for _, agent := range []string{"", "Clash/1.18", "Mihomo/1.19", "Clash.Meta/1.19", "Shadowrocket/2.2", "sing-box/1.12", "Surge/5", "Stash/3", "Hiddify/2", "v2rayN/7", "Quantumult X/1.5", "Loon/3", "Mozilla/5.0 Chrome/140.0 Safari/537.36"} {
		if IsCrawlerUA(agent) {
			t.Fatalf("normal client classified as crawler: %q", agent)
		}
	}
}

func TestCrawlerDetectionIgnoresUnrelatedDeveloperAutomationTools(t *testing.T) {
	for _, agent := range []string{"PostmanRuntime/7.43", "Insomnia/11.0", "node-fetch", "axios/1.8", "undici", "HeadlessChrome/140", "Selenium/4", "Playwright/1", "Puppeteer/24", "phantomjs/2"} {
		if IsCrawlerUA(agent) {
			t.Fatalf("unrelated tool classified as crawler: %q", agent)
		}
	}
}
