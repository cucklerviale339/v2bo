package subscribeguard

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type IPIntelligence struct {
	IP          string `json:"ip"`
	GeoState    string `json:"geo_state"`
	RiskState   string `json:"risk_state"`
	ASN         int64  `json:"asn"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	Network     string `json:"network"`
	Hosting     *bool  `json:"hosting"`
	Proxy       *bool  `json:"proxy"`
	Mobile      *bool  `json:"mobile"`
	CheckedAt   int64  `json:"checked_at"`
	ExpiresAt   int64  `json:"expires_at"`
}

const ipIntelligenceSchema = `
CREATE TABLE IF NOT EXISTS v2_subscribe_ip_intelligence (
 client_ip VARCHAR(64) PRIMARY KEY, profile JSONB NOT NULL DEFAULT '{}',
 last_seen BIGINT NOT NULL, next_attempt BIGINT NOT NULL DEFAULT 0
);
ALTER TABLE v2_subscribe_ip_intelligence ADD COLUMN IF NOT EXISTS lease_until BIGINT NOT NULL DEFAULT 0;
ALTER TABLE v2_subscribe_ip_intelligence ADD COLUMN IF NOT EXISTS lease_version BIGINT NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_subscribe_ip_intelligence_due ON v2_subscribe_ip_intelligence(next_attempt, last_seen);
CREATE TABLE IF NOT EXISTS v2_subscribe_ip_lookup_rate (
 id SMALLINT PRIMARY KEY CHECK (id = 1), next_request BIGINT NOT NULL DEFAULT 0
);
INSERT INTO v2_subscribe_ip_lookup_rate (id) VALUES (1) ON CONFLICT DO NOTHING;`

var nonPublicIPRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

func publicLookupIP(value string) (string, bool) {
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" {
		return "", false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return "", false
	}
	if address.Is6() && !netip.MustParsePrefix("2000::/3").Contains(address) {
		return "", false
	}
	for _, prefix := range nonPublicIPRanges {
		if prefix.Contains(address) {
			return "", false
		}
	}
	return address.String(), true
}

type ipLookup struct{ client *http.Client }

func newIPLookup() ipLookup {
	return ipLookup{client: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (lookup ipLookup) get(ctx context.Context, url string, target any) (int64, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "Forest-Subscription-IP-Monitor/1.0")
	response, err := lookup.client.Do(request)
	if err != nil {
		return 60, errors.New("IP provider unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusTooManyRequests {
		delay, _ := strconv.ParseInt(response.Header.Get("Retry-After"), 10, 64)
		return max(60, min(delay, 3600)), errors.New("IP provider rate limited")
	}
	if response.StatusCode != http.StatusOK {
		return 60, errors.New("IP provider rejected request")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(body) > 65536 {
		return 60, errors.New("IP provider response invalid")
	}
	if err := json.Unmarshal(body, target); err != nil {
		return 60, errors.New("IP provider response invalid")
	}
	return 0, nil
}

func (lookup ipLookup) resolve(ctx context.Context, ip string, now int64) (IPIntelligence, int64) {
	profile := IPIntelligence{IP: ip, GeoState: "unavailable", RiskState: "unavailable", CheckedAt: now, ExpiresAt: now + 3600}
	address, public := publicLookupIP(ip)
	if !public {
		profile.GeoState, profile.RiskState, profile.ExpiresAt = "non_public", "non_public", now+86400
		return profile, 0
	}
	var geo struct {
		IP         string `json:"ip"`
		Success    bool   `json:"success"`
		Country    string `json:"country"`
		Code       string `json:"country_code"`
		Connection struct {
			ASN int64  `json:"asn"`
			ISP string `json:"isp"`
			Org string `json:"org"`
		} `json:"connection"`
	}
	delay, err := lookup.get(ctx, "https://ipwho.is/"+address+"?lang=zh-CN", &geo)
	if err == nil && geo.Success && sameLookupIP(geo.IP, address) && validCountryCode(geo.Code) && geo.Connection.ASN > 0 && geo.Connection.ASN <= 4294967295 {
		profile.GeoState, profile.ASN, profile.CountryCode = "ok", geo.Connection.ASN, strings.ToUpper(geo.Code)
		profile.Country, profile.Network = cleanIPField(geo.Country), cleanIPField(geo.Connection.ISP)
	}
	var risk struct {
		Status  string `json:"status"`
		IP      string `json:"query"`
		Hosting *bool  `json:"hosting"`
		Proxy   *bool  `json:"proxy"`
		Mobile  *bool  `json:"mobile"`
	}
	riskDelay, riskErr := lookup.get(ctx, "http://ip-api.com/json/"+address+"?fields=status,query,proxy,hosting,mobile", &risk)
	if riskErr == nil && risk.Status == "success" && sameLookupIP(risk.IP, address) {
		profile.Hosting, profile.Proxy, profile.Mobile = risk.Hosting, risk.Proxy, risk.Mobile
		if risk.Hosting != nil && risk.Proxy != nil {
			profile.RiskState = "ok"
		}
	}
	if profile.GeoState == "ok" && profile.RiskState == "ok" {
		profile.ExpiresAt = now + 86400
	} else {
		delay = max(delay, 60)
	}
	return profile, max(delay, riskDelay)
}

func sameLookupIP(value, expected string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Unmap().String() == expected
}

func validCountryCode(value string) bool {
	value = strings.ToUpper(value)
	return len(value) == 2 && value[0] >= 'A' && value[0] <= 'Z' && value[1] >= 'A' && value[1] <= 'Z'
}

func cleanIPField(value string) string {
	letters := []rune(strings.Join(strings.Fields(strings.ReplaceAll(value, "\x00", "")), " "))
	return string(letters[:min(len(letters), 160)])
}

func (store *Store) enrichNextIP(ctx context.Context, lookup ipLookup, now int64) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var reservation int64
	err = tx.QueryRowContext(ctx, `UPDATE v2_subscribe_ip_lookup_rate SET next_request=$1::bigint+3 WHERE id=1 AND next_request <= $1
AND EXISTS (SELECT 1 FROM v2_subscribe_monitor_control WHERE id=1 AND ip_enabled) RETURNING next_request`, now).Scan(&reservation)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var ip string
	var leaseVersion int64
	err = tx.QueryRowContext(ctx, `UPDATE v2_subscribe_ip_intelligence SET next_attempt=$1::bigint+60,
lease_until=$1::bigint+60,lease_version=lease_version+1 WHERE client_ip=(
SELECT client_ip FROM v2_subscribe_ip_intelligence WHERE next_attempt <= $1 AND lease_until <= $1 AND last_seen > $1::bigint-86400
ORDER BY next_attempt, last_seen DESC, client_ip LIMIT 1 FOR UPDATE SKIP LOCKED)
RETURNING client_ip,lease_version`, now).Scan(&ip, &leaseVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	profile, delay := lookup.resolve(ctx, ip, now)
	raw, err := json.Marshal(profile)
	if err != nil {
		return err
	}
	if delay > 0 {
		_, err = store.db.ExecContext(ctx, `UPDATE v2_subscribe_ip_lookup_rate SET next_request=GREATEST(next_request,$1) WHERE id=1`, now+delay)
		if err != nil {
			return err
		}
	}
	_, err = store.db.ExecContext(ctx, `UPDATE v2_subscribe_ip_intelligence SET profile=$2, next_attempt=$3,lease_until=0
WHERE client_ip=$1 AND lease_version=$4`, ip, raw, profile.ExpiresAt, leaseVersion)
	return err
}

func readIPIntelligence(raw []byte, ip string, now int64) IPIntelligence {
	profile := IPIntelligence{IP: ip, GeoState: "pending", RiskState: "pending"}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &profile)
	}
	if profile.ExpiresAt > 0 && profile.ExpiresAt <= now {
		profile.GeoState, profile.RiskState = "expired", "expired"
	}
	return profile
}
