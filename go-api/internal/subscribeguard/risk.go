package subscribeguard

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

type RiskMetrics struct {
	Requests24H  int64 `json:"requests_24h"`
	Requests1H   int64 `json:"requests_1h"`
	IPs24H       int64 `json:"ips_24h"`
	IPs10M       int64 `json:"ips_10m"`
	IPs30M       int64 `json:"ips_30m"`
	UAs24H       int64 `json:"uas_24h"`
	UAChanges24H int64 `json:"ua_changes_24h"`
	Errors24H    int64 `json:"errors_24h"`
	ServerErrors int64 `json:"server_errors_24h"`
	Blocked24H   int64 `json:"blocked_24h"`
	ResolvedIPs  int64 `json:"resolved_ips"`
	ASNs24H      int64 `json:"asns_24h"`
	Countries24H int64 `json:"countries_24h"`
	ASNs10M      int64 `json:"asns_10m"`
	Countries10M int64 `json:"countries_10m"`
	Countries30M int64 `json:"countries_30m"`
}

type RiskFactor struct {
	Label  string `json:"label"`
	Points int    `json:"points"`
}

type RiskAssessment struct {
	Score   int          `json:"score"`
	Level   string       `json:"level"`
	Review  bool         `json:"review"`
	Factors []RiskFactor `json:"factors"`
}

type RiskProfile struct {
	Subject       string         `json:"subject"`
	TokenHash     string         `json:"token_hash"`
	UserID        int64          `json:"user_id"`
	Email         string         `json:"email"`
	LastAt        int64          `json:"last_at"`
	IP            string         `json:"ip"`
	UA            string         `json:"ua"`
	Status        int            `json:"status"`
	Blocked       bool           `json:"blocked"`
	UAWhitelisted bool           `json:"ua_whitelisted"`
	Metrics       RiskMetrics    `json:"metrics"`
	Intelligence  IPIntelligence `json:"intelligence"`
	RiskAssessment
}

type RiskFilter struct {
	Keyword  string
	MinScore int
	Current  int
	PageSize int
}

type RiskResult struct {
	Data        []RiskProfile `json:"data"`
	Total       int           `json:"total"`
	Subjects    int           `json:"subjects"`
	Review      int           `json:"review"`
	Current     int           `json:"current"`
	PageSize    int           `json:"page_size"`
	WindowStart int64         `json:"window_start"`
	AssessedAt  int64         `json:"assessed_at"`
	Dropped     int64         `json:"dropped"`
}

func AssessRisk(profile RiskProfile) RiskAssessment {
	result := RiskAssessment{Factors: []RiskFactor{}}
	add := func(label string, points int) {
		if points > 0 {
			result.Factors = append(result.Factors, RiskFactor{Label: label, Points: points})
			result.Score += points
		}
	}
	metrics := profile.Metrics
	add(fmt.Sprintf("1 小时请求 %d 次", metrics.Requests1H), riskTier(metrics.Requests1H, 3, 6, 10))
	add(fmt.Sprintf("24 小时不同 IP %d 个", metrics.IPs24H), riskTier(metrics.IPs24H, 2, 4, 8))
	if metrics.UAChanges24H > 3 {
		add(fmt.Sprintf("24 小时 UA 变化 %d 次", metrics.UAChanges24H), 20)
	} else if metrics.UAChanges24H > 1 {
		add(fmt.Sprintf("24 小时 UA 变化 %d 次", metrics.UAChanges24H), 10)
	}
	if !profile.UAWhitelisted {
		if strings.TrimSpace(profile.UA) == "" {
			add("最近一次请求 UA 为空", 15)
		} else if IsCrawlerUA(profile.UA) {
			add("最近一次请求为脚本 UA", 10)
		}
	}
	if !profile.Blocked && profile.Status >= 400 && profile.Status < 500 {
		add(fmt.Sprintf("最近一次请求失败（HTTP %d）", profile.Status), 12)
	}
	if metrics.Errors24H >= 3 {
		add(fmt.Sprintf("24 小时非拦截的 4xx 响应 %d 次", metrics.Errors24H), 10)
	}
	if metrics.IPs10M >= 3 {
		add(fmt.Sprintf("10 分钟内出现 %d 个不同 IP", metrics.IPs10M), 15)
	}
	if metrics.IPs30M >= 5 {
		add(fmt.Sprintf("30 分钟内出现 %d 个不同 IP", metrics.IPs30M), 15)
	}
	if metrics.ASNs24H > 2 {
		points := 10
		if metrics.ASNs24H > 5 {
			points = 30
		} else if metrics.ASNs24H > 3 {
			points = 20
		}
		add(fmt.Sprintf("24 小时不同 ASN %d 个", metrics.ASNs24H), points)
	}
	if metrics.Countries24H > 1 {
		points := 10
		if metrics.Countries24H > 3 {
			points = 40
		} else if metrics.Countries24H > 2 {
			points = 25
		}
		add(fmt.Sprintf("24 小时不同国家 %d 个", metrics.Countries24H), points)
	}
	severeJump := metrics.Countries10M >= 2 && metrics.ASNs10M >= 2
	if severeJump {
		add("10 分钟内跨多个国家和 ASN", 30)
	} else if metrics.Countries30M >= 2 {
		add("30 分钟内跨国家切换", 20)
	}
	if profile.Intelligence.RiskState == "ok" {
		if profile.Intelligence.Hosting != nil && *profile.Intelligence.Hosting {
			add("最近请求 IP 有 IDC/云服务信号", 10)
		}
		if profile.Intelligence.Proxy != nil && *profile.Intelligence.Proxy {
			add("最近请求 IP 有代理/VPN/Tor 信号", 10)
		}
	}
	if result.Score > 100 {
		result.Score = 100
	}
	result.Level = "low"
	switch {
	case result.Score >= 80:
		result.Level = "critical"
	case result.Score >= 60:
		result.Level = "high"
	case result.Score >= 40:
		result.Level = "medium"
	case result.Score >= 20:
		result.Level = "mild"
	}
	result.Review = result.Score >= 80 && (metrics.IPs24H >= 5 || metrics.Requests1H >= 7 || metrics.IPs10M >= 3 || metrics.ASNs24H >= 3 || severeJump)
	return result
}

func riskTier(value, low, medium, high int64) int {
	switch {
	case value <= low:
		return 0
	case value <= medium:
		return 10
	case value <= high:
		return 20
	default:
		return 35
	}
}

const riskProfilesSQL = `WITH recent AS (
 SELECT event.*, COALESCE(intel.profile, '{}') AS intelligence,
 CASE WHEN intel.profile->>'geo_state' = 'ok' AND (intel.profile->>'expires_at')::bigint > $1 THEN NULLIF(intel.profile->>'asn','0') END AS asn,
 CASE WHEN intel.profile->>'geo_state' = 'ok' AND (intel.profile->>'expires_at')::bigint > $1 THEN NULLIF(intel.profile->>'country_code','') END AS country,
 CASE WHEN token_hash <> '' THEN 'token:' || token_hash ELSE 'user:' || user_id::text END AS subject
 FROM v2_subscribe_guard_event event LEFT JOIN v2_subscribe_ip_intelligence intel ON intel.client_ip=event.client_ip
 WHERE accessed_at > $1::bigint - 86400 AND accessed_at <= $1
 AND (token_hash <> '' OR user_id > 0)
), ordered AS (
 SELECT *, LAG(user_agent) OVER history AS previous_ua,
 LAG(ua_whitelisted) OVER history AS previous_whitelisted,
 ROW_NUMBER() OVER (PARTITION BY subject ORDER BY accessed_at DESC, id DESC) AS recency
 FROM recent WINDOW history AS (PARTITION BY subject ORDER BY accessed_at, id)
), summary AS (
 SELECT subject, MAX(token_hash) AS token_hash, COALESCE(MAX(user_id), 0) AS user_id,
 MAX(accessed_at) AS last_at,
 MAX(client_ip) FILTER (WHERE recency = 1) AS client_ip,
 MAX(user_agent) FILTER (WHERE recency = 1) AS user_agent,
 MAX(status_code) FILTER (WHERE recency = 1) AS status_code,
 BOOL_OR(blocked) FILTER (WHERE recency = 1) AS blocked,
 BOOL_OR(ua_whitelisted) FILTER (WHERE recency = 1) AS ua_whitelisted,
 COUNT(*) AS requests_24h, COUNT(*) FILTER (WHERE accessed_at > $1 - 3600) AS requests_1h,
 COUNT(DISTINCT NULLIF(client_ip, '')) AS ips_24h,
 COUNT(DISTINCT NULLIF(client_ip, '')) FILTER (WHERE accessed_at > $1 - 600) AS ips_10m,
 COUNT(DISTINCT NULLIF(client_ip, '')) FILTER (WHERE accessed_at > $1 - 1800) AS ips_30m,
 COUNT(DISTINCT NULLIF(user_agent, '')) AS uas_24h,
 COUNT(*) FILTER (WHERE previous_ua IS NOT NULL AND previous_ua <> user_agent
   AND NOT ua_whitelisted AND NOT previous_whitelisted) AS ua_changes_24h,
 COUNT(*) FILTER (WHERE NOT blocked AND status_code >= 400 AND status_code < 500) AS errors_24h,
 COUNT(*) FILTER (WHERE status_code >= 500) AS server_errors_24h,
 COUNT(*) FILTER (WHERE blocked) AS blocked_24h,
 COUNT(DISTINCT client_ip) FILTER (WHERE asn IS NOT NULL OR country IS NOT NULL) AS resolved_ips,
 COUNT(DISTINCT asn) AS asns_24h, COUNT(DISTINCT country) AS countries_24h,
 COUNT(DISTINCT asn) FILTER (WHERE accessed_at > $1-600) AS asns_10m,
 COUNT(DISTINCT country) FILTER (WHERE accessed_at > $1-600) AS countries_10m,
 COUNT(DISTINCT country) FILTER (WHERE accessed_at > $1-1800) AS countries_30m,
 MAX(intelligence::text) FILTER (WHERE recency=1) AS intelligence,
 BOOL_OR(client_ip = $2) AS ip_matches
 FROM ordered GROUP BY subject
)
SELECT summary.subject, summary.token_hash, summary.user_id, COALESCE(account.email, ''), summary.last_at,
summary.client_ip, summary.user_agent, summary.status_code, summary.blocked, summary.ua_whitelisted,
requests_24h, requests_1h, ips_24h, ips_10m, ips_30m, uas_24h, ua_changes_24h, errors_24h, server_errors_24h, blocked_24h,
resolved_ips, asns_24h, countries_24h, asns_10m, countries_10m, countries_30m, intelligence
FROM summary LEFT JOIN v2_user account ON account.id = summary.user_id
WHERE $2 = '' OR summary.user_id::text = $2 OR summary.token_hash = $2 OR summary.ip_matches
OR STRPOS(LOWER(COALESCE(account.email, '')), LOWER($2)) > 0`

func (store *Store) Risks(ctx context.Context, filter RiskFilter) (RiskResult, error) {
	return store.risksAt(ctx, filter, time.Now().Unix())
}

func (store *Store) risksAt(ctx context.Context, filter RiskFilter, now int64) (RiskResult, error) {
	result := RiskResult{Data: []RiskProfile{}, Current: filter.Current, PageSize: filter.PageSize,
		WindowStart: now - 86400, AssessedAt: now, Dropped: store.dropped.Load()}
	if filter.Current < 1 || filter.Current > 100000 || filter.PageSize < 1 || filter.PageSize > 100 ||
		filter.MinScore < 0 || filter.MinScore > 100 || len(filter.Keyword) > 255 {
		return result, errors.New("invalid risk query parameters")
	}
	profiles, err := store.riskProfilesAt(ctx, strings.TrimSpace(filter.Keyword), now)
	if err != nil {
		return result, err
	}
	matched := []RiskProfile{}
	for _, profile := range profiles {
		result.Subjects++
		if profile.Review {
			result.Review++
		}
		if profile.Score >= filter.MinScore {
			matched = append(matched, profile)
		}
	}
	sort.Slice(matched, func(left, right int) bool {
		if matched[left].Score != matched[right].Score {
			return matched[left].Score > matched[right].Score
		}
		if matched[left].LastAt != matched[right].LastAt {
			return matched[left].LastAt > matched[right].LastAt
		}
		return matched[left].Subject < matched[right].Subject
	})
	result.Total = len(matched)
	start := (filter.Current - 1) * filter.PageSize
	if start < len(matched) {
		result.Data = matched[start:min(start+filter.PageSize, len(matched))]
	}
	return result, nil
}

func (store *Store) riskProfilesAt(ctx context.Context, keyword string, now int64) ([]RiskProfile, error) {
	query := riskProfilesSQL
	if !store.monitorReady.Load() {
		query = withoutIPCache(query)
	}
	rows, err := store.db.QueryContext(ctx, query, now, keyword)
	if err != nil && monitorSchemaError(err) {
		store.monitorReady.Store(false)
		rows, err = store.db.QueryContext(ctx, withoutIPCache(riskProfilesSQL), now, keyword)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	profiles := []RiskProfile{}
	for rows.Next() {
		var profile RiskProfile
		var rawIntelligence []byte
		metrics := &profile.Metrics
		if err := rows.Scan(&profile.Subject, &profile.TokenHash, &profile.UserID, &profile.Email, &profile.LastAt,
			&profile.IP, &profile.UA, &profile.Status, &profile.Blocked, &profile.UAWhitelisted,
			&metrics.Requests24H, &metrics.Requests1H, &metrics.IPs24H, &metrics.IPs10M, &metrics.IPs30M,
			&metrics.UAs24H, &metrics.UAChanges24H, &metrics.Errors24H, &metrics.ServerErrors, &metrics.Blocked24H,
			&metrics.ResolvedIPs, &metrics.ASNs24H, &metrics.Countries24H, &metrics.ASNs10M, &metrics.Countries10M, &metrics.Countries30M, &rawIntelligence); err != nil {
			return nil, err
		}
		profile.Intelligence = readIPIntelligence(rawIntelligence, profile.IP, now)
		profile.RiskAssessment = AssessRisk(profile)
		profiles = append(profiles, profile)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return profiles, nil
}

func (store *Store) RiskEvents(ctx context.Context, tokenHash string, userID int64) ([]Event, error) {
	condition := `token_hash = $1`
	var identity any = tokenHash
	if tokenHash == "" {
		if userID <= 0 {
			return nil, errors.New("missing risk identity")
		}
		condition, identity = `token_hash = '' AND user_id = $1`, userID
	}
	now := time.Now().Unix()
	rows, err := store.db.QueryContext(ctx, `SELECT id, COALESCE(user_id, 0), event.client_ip, user_agent,
token_hash, endpoint, status_code, blocked, accessed_at FROM v2_subscribe_guard_event event
WHERE (`+condition+`) AND accessed_at > $2::bigint - 86400 AND accessed_at <= $2
ORDER BY accessed_at DESC, id DESC LIMIT 100`, identity, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []Event{}
	for rows.Next() {
		var event Event
		if err := rows.Scan(&event.ID, &event.UserID, &event.IP, &event.UA, &event.TokenHash,
			&event.Endpoint, &event.Status, &event.Blocked, &event.Time); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	store.enrichEvents(ctx, events)
	return events, nil
}
