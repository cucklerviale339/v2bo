package subscribeguard

import (
	"context"
	"database/sql"
	"testing"
)

func TestAssessRiskUsesTokenSignalsAndReviewThreshold(t *testing.T) {
	assessment := AssessRisk(RiskProfile{
		UA: "curl/8.0", Status: 403,
		Metrics: RiskMetrics{Requests1H: 8, IPs24H: 6, IPs10M: 3, UAChanges24H: 4, Errors24H: 3},
	})
	if assessment.Score < 80 || assessment.Level != "critical" || !assessment.Review {
		t.Fatalf("unexpected assessment: %+v", assessment)
	}
	if len(assessment.Factors) < 4 {
		t.Fatalf("expected explainable factors: %+v", assessment.Factors)
	}
}

func TestAssessRiskIgnoresCrawlerSignalForWhitelistedUA(t *testing.T) {
	assessment := AssessRisk(RiskProfile{UA: "curl/8.0", UAWhitelisted: true, Status: 200})
	if assessment.Score != 0 || len(assessment.Factors) != 0 {
		t.Fatalf("whitelisted UA changed risk: %+v", assessment)
	}
}

func TestRiskResponseAndFrequencyBoundaries(t *testing.T) {
	for _, test := range []struct {
		name    string
		profile RiskProfile
		score   int
		level   string
	}{
		{"normal", RiskProfile{UA: "Clash", Status: 200, Metrics: RiskMetrics{Requests1H: 3, IPs24H: 2}}, 0, "low"},
		{"four requests", RiskProfile{UA: "Clash", Status: 200, Metrics: RiskMetrics{Requests1H: 4}}, 10, "low"},
		{"seven requests", RiskProfile{UA: "Clash", Status: 200, Metrics: RiskMetrics{Requests1H: 7}}, 20, "mild"},
		{"eleven requests", RiskProfile{UA: "Clash", Status: 200, Metrics: RiskMetrics{Requests1H: 11}}, 35, "mild"},
		{"server error", RiskProfile{UA: "Clash", Status: 503, Metrics: RiskMetrics{ServerErrors: 10}}, 0, "low"},
		{"blocked", RiskProfile{UA: "Clash", Status: 429, Blocked: true, Metrics: RiskMetrics{Blocked24H: 5}}, 0, "low"},
		{"business error", RiskProfile{UA: "Clash", Status: 403, Metrics: RiskMetrics{Errors24H: 3}}, 22, "mild"},
		{"empty UA", RiskProfile{Status: 200}, 15, "low"},
		{"cap", RiskProfile{UA: "curl", Status: 403, Metrics: RiskMetrics{Requests1H: 100, IPs24H: 100, IPs10M: 20, IPs30M: 20, UAChanges24H: 8, Errors24H: 10}}, 100, "critical"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := AssessRisk(test.profile)
			if result.Score != test.score || result.Level != test.level {
				t.Fatalf("unexpected assessment %+v", result)
			}
		})
	}
}

func testRiskWindows(t *testing.T, db *sql.DB, store *Store) {
	t.Helper()
	const now int64 = 2000000000
	insert := func(user any, token, ip, ua string, status int, blocked, whitelisted bool, at int64) {
		t.Helper()
		_, err := db.Exec(`INSERT INTO v2_subscribe_guard_event
(user_id,token_hash,client_ip,user_agent,endpoint,mode,reason,blocked,status_code,accessed_at,ua_whitelisted)
VALUES ($1,$2,$3,$4,'subscribe','off','',$5,$6,$7,$8)`, user, token, ip, ua, blocked, status, at, whitelisted)
		if err != nil {
			t.Fatal(err)
		}
	}
	insert(42, "risk-a", "192.0.2.10", "Clash", 200, false, false, now-86400)
	insert(42, "risk-a", "192.0.2.11", "Clash", 200, false, false, now-3600)
	insert(42, "risk-a", "192.0.2.12", "curl", 200, false, true, now-600)
	insert(42, "risk-a", "192.0.2.13", "Clash", 503, false, false, now-100)
	insert(nil, "risk-a", "192.0.2.13", "Clash", 403, true, false, now)
	insert(42, "risk-a", "192.0.2.14", "curl", 403, false, false, now+1)
	insert(42, "risk-b", "192.0.2.13", "Clash", 200, false, false, now)
	insert(42, "", "192.0.2.13", "Clash", 200, false, false, now)
	insert(nil, "", "192.0.2.13", "curl", 403, false, false, now)
	result, err := store.risksAt(context.Background(), RiskFilter{Current: 1, PageSize: 20}, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 3 {
		t.Fatalf("tokens and session identities mixed: %+v", result)
	}
	var found bool
	for _, profile := range result.Data {
		if profile.TokenHash != "risk-a" {
			continue
		}
		found = true
		want := RiskMetrics{Requests24H: 4, Requests1H: 3, IPs24H: 3, IPs10M: 1, IPs30M: 2, UAs24H: 2, ServerErrors: 1, Blocked24H: 1}
		if profile.Metrics != want || profile.Score != 10 || profile.UserID != 42 {
			t.Fatalf("invalid window, identity or whitelist aggregation: %+v", profile)
		}
	}
	if !found {
		t.Fatal("missing token")
	}
	filtered, err := store.risksAt(context.Background(), RiskFilter{Keyword: "192.0.2.11", Current: 1, PageSize: 20}, now)
	if err != nil || filtered.Total != 1 || filtered.Data[0].Metrics.Requests24H != 4 {
		t.Fatalf("IP search changed scoring evidence: %+v %v", filtered, err)
	}
	filtered, err = store.risksAt(context.Background(), RiskFilter{MinScore: 10, Current: 2, PageSize: 1}, now)
	if err != nil || filtered.Total != 1 || len(filtered.Data) != 0 {
		t.Fatalf("incorrect post-score pagination: %+v %v", filtered, err)
	}
}
