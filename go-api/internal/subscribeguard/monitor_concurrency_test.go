package subscribeguard

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRiskReasonKeyMatchesEvidence(t *testing.T) {
	profile := RiskProfile{IP: "8.8.8.8", UA: "Clash", Intelligence: IPIntelligence{ASN: 15169, CountryCode: "US"}, RiskAssessment: RiskAssessment{Score: 80, Factors: []RiskFactor{{Label: "reason one", Points: 20}, {Label: "reason two", Points: 30}}}}
	key := riskReasonKey(profile)
	other := profile
	other.Factors = []RiskFactor{profile.Factors[1], profile.Factors[0]}
	other.LastAt = 200
	other.Intelligence.CheckedAt = 200
	if riskReasonKey(other) != key {
		t.Fatal("ordering or refresh changed reason key")
	}
	for _, change := range []func(*RiskProfile){
		func(value *RiskProfile) { value.Score++ },
		func(value *RiskProfile) { value.IP = "1.1.1.1" },
		func(value *RiskProfile) { value.UA = "curl" },
		func(value *RiskProfile) { value.Intelligence.CountryCode = "DE" },
		func(value *RiskProfile) { value.Intelligence.ASN = 123 },
		func(value *RiskProfile) { value.Factors = []RiskFactor{{Label: "new reason", Points: 50}} },
	} {
		other = profile
		change(&other)
		if riskReasonKey(other) == key {
			t.Fatal("changed evidence matched cooldown")
		}
	}
}

func testRiskReviewCooldown(t *testing.T, db *sql.DB, store *Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().Unix()
	profile := RiskProfile{Subject: "token:cooldown-test", TokenHash: "cooldown-test", UserID: 42, IP: "8.8.8.8", UA: "Clash", RiskAssessment: RiskAssessment{Score: 80, Factors: []RiskFactor{{Label: "same evidence", Points: 80}}}}
	save := func(at int64, value RiskProfile) {
		t.Helper()
		if err := store.saveRiskHistory(ctx, []RiskProfile{value}, at); err != nil {
			t.Fatal(err)
		}
	}
	read := func() RiskHistoryResult {
		t.Helper()
		result, err := store.RiskHistory(ctx, RiskHistoryFilter{Keyword: "cooldown-test", Current: 1, PageSize: 100})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	save(now-3600, profile)
	save(now, profile)
	initial := read()
	if initial.Total != 2 {
		t.Fatal("snapshot setup", initial.Total)
	}
	entry := initial.Data[0]
	if err := store.ReviewRisk(ctx, entry.ID, entry.Revision, 7, "false_positive", "已核实"); err != nil {
		t.Fatal(err)
	}
	var reviewedAt int64
	if err := db.QueryRow(`SELECT reviewed_at FROM v2_subscribe_risk_history WHERE id=$1`, entry.ID).Scan(&reviewedAt); err != nil {
		t.Fatal(err)
	}
	updated := read()
	if updated.Data[1].Status != "suppressed" || updated.Data[1].ReviewSource != entry.ID {
		t.Fatal("existing identical pending row not suppressed")
	}
	save(now-7200, profile)
	if read().Data[0].Status != "suppressed" {
		t.Fatal("in-flight assessment ignored newer review")
	}
	save(reviewedAt+3600, profile)
	cooled := read().Data[0]
	if cooled.Status != "suppressed" || cooled.ReviewSource != entry.ID || cooled.CooldownUntil != reviewedAt+86400 || cooled.ReviewedBy != 0 {
		t.Fatalf("cooldown attribution %+v", cooled)
	}
	changed := profile
	changed.Factors = []RiskFactor{{Label: "changed evidence", Points: 80}}
	save(reviewedAt+7200, changed)
	if read().Data[0].Status != "pending" {
		t.Fatal("new reasons suppressed")
	}
	save(reviewedAt+86400, profile)
	if read().Data[0].Status != "pending" {
		t.Fatal("expired cooldown remained active")
	}
	other := profile
	other.Subject = "token:other-subject"
	other.TokenHash = "other-subject"
	save(reviewedAt+3600, other)
	result, err := store.RiskHistory(ctx, RiskHistoryFilter{Keyword: "other-subject", Current: 1, PageSize: 20})
	if err != nil || result.Data[0].Status != "pending" {
		t.Fatal("cooldown leaked between tokens", err)
	}
	if err := store.ReviewRisk(ctx, result.Data[0].ID, 0, 7, "handled", "普通处理"); err != nil {
		t.Fatal(err)
	}
	save(reviewedAt+7200, other)
	result, err = store.RiskHistory(ctx, RiskHistoryFilter{Keyword: "other-subject", Current: 1, PageSize: 20})
	if err != nil || result.Data[0].Status != "pending" {
		t.Fatal("handled incorrectly enabled cooldown", err)
	}
	legacy := profile
	legacy.Subject = "token:legacy-review"
	legacy.TokenHash = "legacy-review"
	save(now, legacy)
	if _, err := db.Exec(`UPDATE v2_subscribe_risk_history SET reason_key='' WHERE subject=$1`, legacy.Subject); err != nil {
		t.Fatal(err)
	}
	result, err = store.RiskHistory(ctx, RiskHistoryFilter{Keyword: legacy.TokenHash, Current: 1, PageSize: 20})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReviewRisk(ctx, result.Data[0].ID, 0, 7, "false_positive", "旧版记录"); err != nil {
		t.Fatal(err)
	}
	save(now+3600, legacy)
	result, err = store.RiskHistory(ctx, RiskHistoryFilter{Keyword: legacy.TokenHash, Current: 1, PageSize: 20})
	if err != nil || result.Data[0].Status != "suppressed" {
		t.Fatal("review of old snapshot not compatible", err)
	}
}

func testIPLeaseRetry(t *testing.T, db *sql.DB, store *Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	now := time.Now().Unix()
	for _, query := range []string{
		`UPDATE v2_subscribe_ip_intelligence SET next_attempt=$1::bigint+2592000,lease_until=0`,
		`UPDATE v2_subscribe_ip_lookup_rate SET next_request=$1::bigint-1`,
		`UPDATE v2_subscribe_ip_intelligence SET next_attempt=0,last_seen=$1,profile='{"geo_state":"unavailable","risk_state":"unavailable"}' WHERE client_ip='8.8.8.8'`,
	} {
		if _, err := db.Exec(query, now); err != nil {
			t.Fatal(err)
		}
	}
	started, release := make(chan struct{}), make(chan struct{})
	var startedOnce, releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var calls atomic.Int64
	fixture := fixtureIPLookup(t, `{"status":"success","query":"8.8.8.8","hosting":true,"proxy":false}`, 200, &calls)
	lookup := ipLookup{client: &http.Client{Transport: ipTestTransport(func(request *http.Request) (*http.Response, error) {
		startedOnce.Do(func() { close(started) })
		select {
		case <-release:
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}
		return fixture.client.Transport.RoundTrip(request)
	})}}
	done := make(chan error, 1)
	go func() { done <- store.enrichNextIP(ctx, lookup, now) }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("lookup did not start")
	}
	for index := 0; index < 3; index++ {
		if _, err := store.RetryIPLookups(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var leaseUntil, nextAttempt, version int64
	if err := db.QueryRow(`SELECT lease_until,next_attempt,lease_version FROM v2_subscribe_ip_intelligence WHERE client_ip='8.8.8.8'`).Scan(&leaseUntil, &nextAttempt, &version); err != nil || leaseUntil != now+60 || nextAttempt != now+60 {
		t.Fatal("retry stole active lease", err, leaseUntil, nextAttempt)
	}
	if _, err := db.Exec(`UPDATE v2_subscribe_ip_intelligence SET next_attempt=$1::bigint+2592000 WHERE client_ip<>'8.8.8.8'`, now); err != nil {
		t.Fatal(err)
	}
	var secondCalls atomic.Int64
	second := fixtureIPLookup(t, `{"status":"success","query":"8.8.8.8","hosting":false,"proxy":false}`, 200, &secondCalls)
	if err := NewStore(db, "key").enrichNextIP(ctx, second, now+4); err != nil {
		t.Fatal(err)
	}
	if secondCalls.Load() != 0 {
		t.Fatal("same IP claimed while lease active")
	}
	if err := NewStore(db, "key").enrichNextIP(ctx, second, now+61); err != nil {
		t.Fatal(err)
	}
	if secondCalls.Load() != 2 {
		t.Fatal("expired lease not reclaimed", secondCalls.Load())
	}
	releaseOnce.Do(func() { close(release) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var raw []byte
	var savedVersion int64
	if err := db.QueryRow(`SELECT profile,lease_until,lease_version FROM v2_subscribe_ip_intelligence WHERE client_ip='8.8.8.8'`).Scan(&raw, &leaseUntil, &savedVersion); err != nil {
		t.Fatal(err)
	}
	var profile IPIntelligence
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatal(err)
	}
	if savedVersion != version+1 || leaseUntil != 0 || profile.CheckedAt != now+61 || profile.Hosting == nil || *profile.Hosting {
		t.Fatal("late old lookup overwrote newer result")
	}
}
