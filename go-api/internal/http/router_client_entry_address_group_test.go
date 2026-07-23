package httpapi

import (
	"context"
	"testing"

	usersvc "forest/go-api/internal/user"
)

func TestBuildForestEntryProviderProxiesPreservesMatchedAddressGroupHost(t *testing.T) {
	servers := []map[string]any{
		{
			"id":      int64(7),
			"type":    "vmess",
			"name":    "VMess-1",
			"host":    usersvc.AddressGroupHost("address-group.example.com"),
			"port":    int64(443),
			"network": "tcp",
			"tls":     int64(0),
		},
	}
	group := usersvc.ClientEntryGroup{
		IPs: []usersvc.ClientEntryGroupIP{{IP: "entry-group.example.com"}},
	}

	proxies := buildForestEntryProviderProxies(context.Background(), "user-uuid", servers, group, nil)
	if len(proxies) != 1 {
		t.Fatalf("expected one address-group proxy, got %#v", proxies)
	}
	proxy, ok := proxies[0].(map[string]any)
	if !ok {
		t.Fatalf("expected proxy object, got %#v", proxies[0])
	}
	if got := serverString(proxy, "server"); got != "address-group.example.com" {
		t.Fatalf("address group host was overwritten: got %q", got)
	}
}

func TestBuildForestEntryProviderProxiesUsesEntryIPWithoutAddressGroupMatch(t *testing.T) {
	servers := []map[string]any{
		{
			"id":      int64(7),
			"type":    "vmess",
			"name":    "VMess-1",
			"host":    "original.example.com",
			"port":    int64(443),
			"network": "tcp",
			"tls":     int64(0),
		},
	}
	group := usersvc.ClientEntryGroup{
		IPs: []usersvc.ClientEntryGroupIP{{IP: "entry-group.example.com"}},
	}

	proxies := buildForestEntryProviderProxies(context.Background(), "user-uuid", servers, group, nil)
	if len(proxies) != 1 {
		t.Fatalf("expected one entry-group proxy, got %#v", proxies)
	}
	proxy, ok := proxies[0].(map[string]any)
	if !ok {
		t.Fatalf("expected proxy object, got %#v", proxies[0])
	}
	if got := serverString(proxy, "server"); got != "entry-group.example.com" {
		t.Fatalf("expected entry group host, got %q", got)
	}
}
