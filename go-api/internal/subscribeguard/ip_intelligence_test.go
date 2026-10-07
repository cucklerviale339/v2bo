package subscribeguard

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

type ipTestTransport func(*http.Request) (*http.Response, error)

func (transport ipTestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func fixtureIPLookup(t *testing.T, body string, status int, calls *atomic.Int64) ipLookup {
	t.Helper()
	return ipLookup{client: &http.Client{Transport: ipTestTransport(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		if strings.Contains(request.URL.RawQuery, "token") || request.Header.Get("Authorization") != "" {
			t.Error("credential sent to provider")
		}
		responseBody := body
		if request.URL.Host == "ipwho.is" {
			responseBody = `{"success":true,"ip":"8.8.8.8","country":"United States","country_code":"US","connection":{"asn":15169,"isp":"Google"}}`
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Retry-After": []string{"120"}}, Body: io.NopCloser(strings.NewReader(responseBody))}, nil
	})}}
}

func TestIPLookupPrivateAddressesNeverLeaveServer(t *testing.T) {
	var calls atomic.Int64
	lookup := fixtureIPLookup(t, "{}", 200, &calls)
	for _, address := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.169.254", "192.0.2.1", "2001:db8::1", "fc00::1", "fe80::1%eth0", "64:ff9b::a00:1", "224.0.0.1", "not-ip", "8.8.8.8/path"} {
		profile, _ := lookup.resolve(context.Background(), address, 100)
		if profile.GeoState != "non_public" {
			t.Fatalf("address not excluded: %s", address)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("private address queried externally")
	}
	for _, address := range []string{"8.8.8.8", "::ffff:8.8.8.8", "2606:4700:4700::1111"} {
		if _, ok := publicLookupIP(address); !ok {
			t.Fatalf("public IP rejected: %s", address)
		}
	}
}

func TestIPLookupUnknownIsNotFalse(t *testing.T) {
	for _, test := range []struct {
		name, body string
		status     int
		state      string
		hosting    *bool
	}{
		{"known", `{"status":"success","query":"8.8.8.8","hosting":true,"proxy":false,"mobile":false}`, 200, "ok", boolPointer(true)},
		{"missing fields", `{"status":"success","query":"8.8.8.8"}`, 200, "unavailable", nil},
		{"wrong IP", `{"status":"success","query":"9.9.9.9","hosting":true,"proxy":true}`, 200, "unavailable", nil},
		{"limited", `{}`, 429, "unavailable", nil},
		{"oversize", strings.Repeat("x", 65537), 200, "unavailable", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int64
			profile, delay := fixtureIPLookup(t, test.body, test.status, &calls).resolve(context.Background(), "8.8.8.8", 100)
			if profile.RiskState != test.state || (profile.Hosting == nil) != (test.hosting == nil) {
				t.Fatalf("wrong unknown handling: %+v", profile)
			}
			if test.status == 429 && delay != 120 {
				t.Fatalf("missing provider backoff %d", delay)
			}
			if test.status == 200 && (profile.ASN != 15169 || profile.CountryCode != "US") {
				t.Fatal("geo discarded on partial error")
			}
			if test.state == "ok" && profile.ExpiresAt != 86500 {
				t.Fatal("success cache TTL")
			}
			if test.state != "ok" && profile.ExpiresAt != 3700 {
				t.Fatal("failure cache TTL")
			}
		})
	}
}

func boolPointer(value bool) *bool { return &value }

func TestIPRiskOnlyUsesFreshExplicitSignals(t *testing.T) {
	base := RiskProfile{UA: "Clash", Status: 200, Intelligence: IPIntelligence{RiskState: "ok", Hosting: boolPointer(true), Proxy: boolPointer(true)}}
	if AssessRisk(base).Score != 20 {
		t.Fatal("missing IP risk factors")
	}
	base.Intelligence.RiskState = "expired"
	if AssessRisk(base).Score != 0 {
		t.Fatal("expired signals added risk")
	}
	base.Intelligence = IPIntelligence{}
	base.Metrics = RiskMetrics{ASNs24H: 3, Countries24H: 3, ASNs10M: 2, Countries10M: 2, Countries30M: 3}
	assessment := AssessRisk(base)
	if assessment.Score != 65 || len(assessment.Factors) != 3 {
		t.Fatalf("cross-country double-count: %+v", assessment)
	}
	profile := readIPIntelligence([]byte(`{"geo_state":"ok","risk_state":"ok","expires_at":100}`), "8.8.8.8", 100)
	if profile.GeoState != "expired" || profile.RiskState != "expired" {
		t.Fatal("expired cache treated as current")
	}
}

func testIPIntelligenceDatabase(t *testing.T, db *sql.DB, store *Store) {
	t.Helper()
	ctx := context.Background()
	var calls atomic.Int64
	lookup := fixtureIPLookup(t, `{"status":"success","query":"8.8.8.8","hosting":true,"proxy":false,"mobile":false}`, 200, &calls)
	const now int64 = 2000000000
	_, err := db.Exec(`INSERT INTO v2_subscribe_ip_intelligence (client_ip,last_seen) VALUES ('8.8.8.8',$1)`, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.enrichNextIP(ctx, lookup, now); err != nil {
		t.Fatal(err)
	}
	if err := NewStore(db, "key").enrichNextIP(ctx, lookup, now); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("duplicate cross-instance lookups: %d", calls.Load())
	}
	if err := store.enrichNextIP(ctx, lookup, now+4); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("cache not reused")
	}
	profile := IPIntelligence{IP: "192.0.2.13", GeoState: "ok", RiskState: "ok", ASN: 123, CountryCode: "DE", Country: "Germany", Hosting: boolPointer(true), Proxy: boolPointer(true), CheckedAt: now, ExpiresAt: now + 3600}
	raw, _ := json.Marshal(profile)
	_, err = db.Exec(`INSERT INTO v2_subscribe_ip_intelligence (client_ip,profile,last_seen,next_attempt) VALUES ($1,$2,$3,$4) ON CONFLICT(client_ip) DO UPDATE SET profile=EXCLUDED.profile,next_attempt=EXCLUDED.next_attempt`, profile.IP, raw, now, now+3600)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.risksAt(ctx, RiskFilter{Keyword: "risk-a", Current: 1, PageSize: 20}, now)
	if err != nil || len(result.Data) != 1 {
		t.Fatalf("enriched query: %+v %v", result, err)
	}
	row := result.Data[0]
	if row.Score != 30 || row.Metrics.ResolvedIPs != 1 || row.Metrics.ASNs24H != 1 || row.Metrics.Countries24H != 1 || row.Intelligence.CountryCode != "DE" {
		t.Fatalf("enriched metrics: %+v", row)
	}
	expired, err := store.risksAt(ctx, RiskFilter{Keyword: "risk-a", Current: 1, PageSize: 20}, now+3600)
	if err != nil || expired.Data[0].Metrics.ResolvedIPs != 0 {
		t.Fatal("expired geography counted", err)
	}
	events, err := store.RiskEvents(ctx, "", 42)
	if err != nil || len(events) == 0 || events[0].Intelligence == nil {
		t.Fatal("request enrichment failed", err)
	}
}
