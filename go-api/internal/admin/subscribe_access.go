package admin

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"forest/go-api/internal/platform/postgres"
)

const dailyLowTrafficThresholdBytes int64 = 200 * 1024

func (s *DBService) GetSubscribeAccessStats(ctx context.Context, req SubscribeAccessStatsRequest) (map[string]any, error) {
	if s == nil || s.db == nil {
		return nil, ErrUnavailable
	}
	s.subscribeAccessOnce.Do(func() {
		s.subscribeAccessErr = postgres.EnsureSubscribeAccessSchema(ctx, s.db)
	})
	if s.subscribeAccessErr != nil {
		return nil, s.subscribeAccessErr
	}

	current := req.Current
	if current <= 0 {
		current = 1
	}
	pageSize := req.PageSize
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	var requests, users, ips, userAgents int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(DISTINCT user_id),
COUNT(DISTINCT NULLIF(client_ip, '')), COUNT(DISTINCT NULLIF(user_agent, ''))
FROM v2_subscribe_access_log`).Scan(&requests, &users, &ips, &userAgents); err != nil {
		return nil, fmt.Errorf("query subscribe access summary: %w", err)
	}

	condition := ""
	args := make([]any, 0, 3)
	keyword := strings.TrimSpace(req.Keyword)
	if keyword != "" {
		if userID, err := strconv.ParseInt(keyword, 10, 64); err == nil {
			condition = " WHERE l.user_id = $1"
			args = append(args, userID)
		} else {
			condition = " WHERE LOWER(u.email) LIKE LOWER($1)"
			args = append(args, "%"+keyword+"%")
		}
	}

	var total int64
	countQuery := `SELECT COUNT(DISTINCT l.user_id)
FROM v2_subscribe_access_log l
JOIN v2_user u ON u.id = l.user_id` + condition
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count subscribe access users: %w", err)
	}

	limitPlaceholder := len(args) + 1
	offsetPlaceholder := len(args) + 2
	orderBy := "MAX(l.accessed_at) DESC, l.user_id DESC"
	if req.Sort == "count" {
		orderBy = "COUNT(*) DESC, l.user_id DESC"
	} else if req.Sort == "ip_count" {
		orderBy = "COUNT(DISTINCT NULLIF(l.client_ip, '')) DESC, COUNT(*) DESC, l.user_id DESC"
	}
	query := `SELECT l.user_id, COALESCE(u.email, ''), COUNT(*),
COUNT(DISTINCT NULLIF(l.client_ip, '')), COUNT(DISTINCT NULLIF(l.user_agent, '')),
MAX(l.accessed_at),
COALESCE((ARRAY_AGG(l.client_ip ORDER BY l.accessed_at DESC) FILTER (WHERE l.client_ip <> ''))[1], ''),
COALESCE((ARRAY_AGG(l.user_agent ORDER BY l.accessed_at DESC) FILTER (WHERE l.user_agent <> ''))[1], '')
FROM v2_subscribe_access_log l
JOIN v2_user u ON u.id = l.user_id` + condition + `
GROUP BY l.user_id, u.email
ORDER BY ` + orderBy + `
LIMIT $` + strconv.Itoa(limitPlaceholder) + ` OFFSET $` + strconv.Itoa(offsetPlaceholder)
	args = append(args, pageSize, (current-1)*pageSize)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query subscribe access users: %w", err)
	}
	defer rows.Close()

	data := make([]map[string]any, 0)
	for rows.Next() {
		var userID, count, ipCount, uaCount, lastAt int64
		var email, lastIP, lastUA string
		if err := rows.Scan(&userID, &email, &count, &ipCount, &uaCount, &lastAt, &lastIP, &lastUA); err != nil {
			return nil, fmt.Errorf("scan subscribe access user: %w", err)
		}
		data = append(data, map[string]any{
			"user_id": userID, "email": email, "count": count,
			"ip_count": ipCount, "ua_count": uaCount, "last_at": lastAt,
			"last_ip": lastIP, "last_ua": lastUA,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subscribe access users: %w", err)
	}

	topIPs, err := s.subscribeAccessTopValues(ctx, "client_ip", "ip")
	if err != nil {
		return nil, err
	}
	topUAs, err := s.subscribeAccessTopValues(ctx, "user_agent", "ua")
	if err != nil {
		return nil, err
	}
	recent, err := s.subscribeAccessRecent(ctx, 0)
	if err != nil {
		return nil, err
	}
	var keepDays int64
	if err := s.db.QueryRowContext(ctx, `SELECT log_keep_days FROM v2_subscribe_access_config WHERE id = 1`).Scan(&keepDays); err != nil {
		return nil, fmt.Errorf("query subscribe access retention: %w", err)
	}

	return map[string]any{
		"summary": map[string]any{"requests": requests, "users": users, "ips": ips, "user_agents": userAgents},
		"data":    data, "total": total, "current": current, "page_size": pageSize,
		"top_ips": topIPs, "top_uas": topUAs, "recent": recent, "log_keep_days": keepDays,
	}, nil
}

func (s *DBService) subscribeAccessTopValues(ctx context.Context, column, resultKey string) ([]map[string]any, error) {
	query := `SELECT ` + column + `, COUNT(*) FROM v2_subscribe_access_log
WHERE ` + column + ` <> '' GROUP BY ` + column + ` ORDER BY COUNT(*) DESC, ` + column + ` LIMIT 20`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query top subscribe access %s: %w", resultKey, err)
	}
	defer rows.Close()
	data := make([]map[string]any, 0)
	for rows.Next() {
		var value string
		var count int64
		if err := rows.Scan(&value, &count); err != nil {
			return nil, fmt.Errorf("scan top subscribe access %s: %w", resultKey, err)
		}
		data = append(data, map[string]any{resultKey: value, "count": count})
	}
	return data, rows.Err()
}

func (s *DBService) subscribeAccessRecent(ctx context.Context, userID int64) ([]map[string]any, error) {
	condition := ""
	args := []any{}
	if userID > 0 {
		condition = " WHERE l.user_id = $1"
		args = append(args, userID)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT l.id, l.user_id, COALESCE(u.email, ''), l.client_ip, l.user_agent, l.accessed_at
FROM v2_subscribe_access_log l JOIN v2_user u ON u.id = l.user_id`+condition+`
ORDER BY l.accessed_at DESC, l.id DESC LIMIT 100`, args...)
	if err != nil {
		return nil, fmt.Errorf("query recent subscribe access: %w", err)
	}
	defer rows.Close()
	data := make([]map[string]any, 0)
	for rows.Next() {
		var id, itemUserID, accessedAt int64
		var email, ip, ua string
		if err := rows.Scan(&id, &itemUserID, &email, &ip, &ua, &accessedAt); err != nil {
			return nil, fmt.Errorf("scan recent subscribe access: %w", err)
		}
		data = append(data, map[string]any{"id": id, "user_id": itemUserID, "email": email, "ip": ip, "ua": ua, "accessed_at": accessedAt})
	}
	return data, rows.Err()
}

func (s *DBService) GetSubscribeAccessUserDetail(ctx context.Context, userID int64) (map[string]any, error) {
	if s == nil || s.db == nil {
		return nil, ErrUnavailable
	}
	if userID <= 0 {
		return nil, fmt.Errorf("用户 ID 无效")
	}
	s.subscribeAccessOnce.Do(func() { s.subscribeAccessErr = postgres.EnsureSubscribeAccessSchema(ctx, s.db) })
	if s.subscribeAccessErr != nil {
		return nil, s.subscribeAccessErr
	}
	var email, planName string
	var planID, expiredAt, transferEnable, used, banned int64
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(u.email, ''), COALESCE(u.plan_id, 0), COALESCE(p.name, ''),
COALESCE(u.expired_at, 0), u.transfer_enable, u.u + u.d, u.banned
FROM v2_user u LEFT JOIN v2_plan p ON p.id = u.plan_id WHERE u.id = $1`, userID).
		Scan(&email, &planID, &planName, &expiredAt, &transferEnable, &used, &banned)
	if err != nil {
		return nil, fmt.Errorf("query subscribe access user: %w", err)
	}
	loadGroups := func(column, key string) ([]map[string]any, error) {
		rows, err := s.db.QueryContext(ctx, `SELECT `+column+`, COUNT(*) FROM v2_subscribe_access_log
WHERE user_id = $1 AND `+column+` <> '' GROUP BY `+column+` ORDER BY COUNT(*) DESC, `+column, userID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		items := make([]map[string]any, 0)
		for rows.Next() {
			var value string
			var count int64
			if err := rows.Scan(&value, &count); err != nil {
				return nil, err
			}
			items = append(items, map[string]any{key: value, "count": count})
		}
		return items, rows.Err()
	}
	ips, err := loadGroups("client_ip", "ip")
	if err != nil {
		return nil, fmt.Errorf("query user IPs: %w", err)
	}
	uas, err := loadGroups("user_agent", "ua")
	if err != nil {
		return nil, fmt.Errorf("query user UAs: %w", err)
	}
	recent, err := s.subscribeAccessRecent(ctx, userID)
	if err != nil {
		return nil, err
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM v2_subscribe_access_log WHERE user_id = $1`, userID).Scan(&total); err != nil {
		return nil, err
	}
	return map[string]any{"user_id": userID, "email": email, "plan_id": planID, "plan_name": planName,
		"expired_at": expiredAt, "transfer_enable": transferEnable, "used": used, "banned": banned,
		"total": total, "ip_count": len(ips), "ua_count": len(uas), "ips": ips, "uas": uas, "recent": recent}, nil
}

func (s *DBService) SearchSubscribeAccessByUA(ctx context.Context, keyword string, current, pageSize int64) (map[string]any, error) {
	if s == nil || s.db == nil {
		return nil, ErrUnavailable
	}
	s.subscribeAccessOnce.Do(func() { s.subscribeAccessErr = postgres.EnsureSubscribeAccessSchema(ctx, s.db) })
	if s.subscribeAccessErr != nil {
		return nil, s.subscribeAccessErr
	}
	keyword = strings.TrimSpace(keyword)
	if current <= 0 {
		current = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	pattern := "%" + keyword + "%"
	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT user_id) FROM v2_subscribe_access_log WHERE LOWER(user_agent) LIKE LOWER($1)`, pattern).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT l.user_id, COALESCE(u.email, ''), COUNT(*), COUNT(DISTINCT NULLIF(l.client_ip, '')),
COUNT(DISTINCT NULLIF(l.user_agent, '')), MAX(l.accessed_at)
FROM v2_subscribe_access_log l JOIN v2_user u ON u.id = l.user_id
WHERE LOWER(l.user_agent) LIKE LOWER($1) GROUP BY l.user_id, u.email
ORDER BY COUNT(*) DESC, l.user_id DESC LIMIT $2 OFFSET $3`, pattern, pageSize, (current-1)*pageSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	data := make([]map[string]any, 0)
	for rows.Next() {
		var userID, count, ipCount, uaCount, lastAt int64
		var email string
		if err := rows.Scan(&userID, &email, &count, &ipCount, &uaCount, &lastAt); err != nil {
			return nil, err
		}
		data = append(data, map[string]any{"user_id": userID, "email": email, "count": count, "ip_count": ipCount, "ua_count": uaCount, "last_at": lastAt})
	}
	return map[string]any{"data": data, "total": total, "current": current, "page_size": pageSize, "keyword": keyword}, rows.Err()
}

func (s *DBService) SetSubscribeAccessRetention(ctx context.Context, days int64) (bool, error) {
	if s == nil || s.db == nil {
		return false, ErrUnavailable
	}
	if days < 1 || days > 3650 {
		return false, fmt.Errorf("保留天数无效")
	}
	s.subscribeAccessOnce.Do(func() { s.subscribeAccessErr = postgres.EnsureSubscribeAccessSchema(ctx, s.db) })
	if s.subscribeAccessErr != nil {
		return false, s.subscribeAccessErr
	}
	now := time.Now().Unix()
	if _, err := s.db.ExecContext(ctx, `UPDATE v2_subscribe_access_config SET log_keep_days = $1, updated_at = $2 WHERE id = 1`, days, now); err != nil {
		return false, err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM v2_subscribe_access_log WHERE accessed_at < $1`, now-days*86400); err != nil {
		return false, err
	}
	return true, nil
}

func (s *DBService) GetDailyLowTrafficUsers(ctx context.Context, current, pageSize, thresholdBytes int64) (map[string]any, error) {
	if s == nil || s.db == nil {
		return nil, ErrUnavailable
	}
	s.subscribeAccessOnce.Do(func() {
		s.subscribeAccessErr = postgres.EnsureSubscribeAccessSchema(ctx, s.db)
	})
	if s.subscribeAccessErr != nil {
		return nil, s.subscribeAccessErr
	}
	if current <= 0 {
		current = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	if thresholdBytes <= 0 {
		thresholdBytes = dailyLowTrafficThresholdBytes
	}

	now := time.Now()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Unix()
	dayEnd := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location()).Unix()
	dailyQuery := `WITH daily AS (
SELECT user_id,
CAST(ROUND(SUM((CAST(u AS numeric) + CAST(d AS numeric)) * server_rate)) AS bigint) AS traffic_bytes
FROM v2_stat_user
WHERE record_type = 'd' AND record_at >= $1 AND record_at < $2
GROUP BY user_id
HAVING SUM((CAST(u AS numeric) + CAST(d AS numeric)) * server_rate) > 0
AND SUM((CAST(u AS numeric) + CAST(d AS numeric)) * server_rate) <= $3
)`

	var total int64
	if err := s.db.QueryRowContext(ctx, dailyQuery+`
SELECT COUNT(*) FROM daily`, dayStart, dayEnd, thresholdBytes).Scan(&total); err != nil {
		return nil, fmt.Errorf("count daily low traffic users: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, dailyQuery+`
SELECT daily.user_id, COALESCE(u.email, ''), daily.traffic_bytes,
COALESCE(access.client_ip, ''), COALESCE(access.user_agent, ''), COALESCE(access.accessed_at, 0)
FROM daily
JOIN v2_user u ON u.id = daily.user_id
LEFT JOIN LATERAL (
  SELECT client_ip, user_agent, accessed_at
  FROM v2_subscribe_access_log
  WHERE user_id = daily.user_id
  ORDER BY accessed_at DESC
  LIMIT 1
) access ON TRUE
ORDER BY daily.traffic_bytes ASC, daily.user_id ASC
LIMIT $4 OFFSET $5`, dayStart, dayEnd, thresholdBytes, pageSize, (current-1)*pageSize)
	if err != nil {
		return nil, fmt.Errorf("query daily low traffic users: %w", err)
	}
	defer rows.Close()

	data := make([]map[string]any, 0)
	for rows.Next() {
		var userID, trafficBytes, lastAt int64
		var email, lastIP, lastUA string
		if err := rows.Scan(&userID, &email, &trafficBytes, &lastIP, &lastUA, &lastAt); err != nil {
			return nil, fmt.Errorf("scan daily low traffic user: %w", err)
		}
		data = append(data, map[string]any{
			"user_id": userID, "email": email, "traffic_bytes": trafficBytes,
			"last_ip": lastIP, "last_ua": lastUA, "last_at": lastAt,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate daily low traffic users: %w", err)
	}

	return map[string]any{
		"data": data, "total": total, "current": current, "page_size": pageSize,
		"threshold_bytes": thresholdBytes, "day_start": dayStart,
	}, nil
}

func (s *DBService) GetConsecutiveLowTrafficUsers(ctx context.Context, current, pageSize, thresholdBytes, days int64) (map[string]any, error) {
	if s == nil || s.db == nil {
		return nil, ErrUnavailable
	}
	s.subscribeAccessOnce.Do(func() {
		s.subscribeAccessErr = postgres.EnsureSubscribeAccessSchema(ctx, s.db)
	})
	if s.subscribeAccessErr != nil {
		return nil, s.subscribeAccessErr
	}
	if current <= 0 {
		current = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	if thresholdBytes <= 0 {
		thresholdBytes = dailyLowTrafficThresholdBytes
	}
	if days <= 0 {
		days = 3
	}

	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	rangeStart := todayStart.AddDate(0, 0, -int(days)+1).Unix()
	rangeEnd := todayStart.AddDate(0, 0, 1).Unix()
	dates := make([]int64, 0, days)
	for offset := int64(0); offset < days; offset++ {
		dates = append(dates, todayStart.AddDate(0, 0, -int(days)+1+int(offset)).Unix())
	}

	qualifiedQuery := `WITH daily AS (
SELECT user_id, record_at,
SUM((CAST(u AS numeric) + CAST(d AS numeric)) * server_rate) AS traffic_value
FROM v2_stat_user
WHERE record_type = 'd' AND record_at >= $1 AND record_at < $2
GROUP BY user_id, record_at
), qualified AS (
SELECT user_id
FROM daily
GROUP BY user_id
HAVING COUNT(*) = $4 AND MIN(traffic_value) > 0 AND MAX(traffic_value) <= $3
)`

	var total int64
	if err := s.db.QueryRowContext(ctx, qualifiedQuery+`
SELECT COUNT(*) FROM qualified`, rangeStart, rangeEnd, thresholdBytes, days).Scan(&total); err != nil {
		return nil, fmt.Errorf("count consecutive low traffic users: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, qualifiedQuery+`, selected AS (
SELECT user_id FROM qualified ORDER BY user_id ASC LIMIT $5 OFFSET $6
)
SELECT selected.user_id, COALESCE(u.email, ''), daily.record_at,
CAST(ROUND(daily.traffic_value) AS bigint),
COALESCE(access.client_ip, ''), COALESCE(access.user_agent, ''), COALESCE(access.accessed_at, 0)
FROM selected
JOIN v2_user u ON u.id = selected.user_id
JOIN daily ON daily.user_id = selected.user_id
LEFT JOIN LATERAL (
  SELECT client_ip, user_agent, accessed_at
  FROM v2_subscribe_access_log
  WHERE user_id = selected.user_id
  ORDER BY accessed_at DESC
  LIMIT 1
) access ON TRUE
ORDER BY selected.user_id ASC, daily.record_at ASC`, rangeStart, rangeEnd, thresholdBytes, days, pageSize, (current-1)*pageSize)
	if err != nil {
		return nil, fmt.Errorf("query consecutive low traffic users: %w", err)
	}
	defer rows.Close()

	data := make([]map[string]any, 0)
	indexByUserID := make(map[int64]int)
	for rows.Next() {
		var userID, recordAt, trafficBytes, lastAt int64
		var email, lastIP, lastUA string
		if err := rows.Scan(&userID, &email, &recordAt, &trafficBytes, &lastIP, &lastUA, &lastAt); err != nil {
			return nil, fmt.Errorf("scan consecutive low traffic user: %w", err)
		}
		index, ok := indexByUserID[userID]
		if !ok {
			data = append(data, map[string]any{
				"user_id": userID, "email": email, "last_ip": lastIP,
				"last_ua": lastUA, "last_at": lastAt, "daily_traffic": []map[string]any{},
			})
			index = len(data) - 1
			indexByUserID[userID] = index
		}
		dailyTraffic := data[index]["daily_traffic"].([]map[string]any)
		data[index]["daily_traffic"] = append(dailyTraffic, map[string]any{
			"record_at": recordAt, "traffic_bytes": trafficBytes,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate consecutive low traffic users: %w", err)
	}

	return map[string]any{
		"data": data, "total": total, "current": current, "page_size": pageSize,
		"threshold_bytes": thresholdBytes, "days": days, "dates": dates,
	}, nil
}
