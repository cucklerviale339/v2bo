package subscribeguard

import (
	"context"
	"encoding/json"
	"errors"
)

func (store *Store) queryObjects(ctx context.Context, query string, args ...any) ([]map[string]any, error) {
	rows, err := store.db.QueryContext(ctx, "SELECT row_to_json(result) FROM ("+query+") result", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var item map[string]any
		if err := json.Unmarshal(raw, &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (store *Store) Analytics(ctx context.Context, userID int64) (map[string]any, error) {
	condition := ` FROM v2_subscribe_guard_event WHERE ($1::bigint = 0 OR user_id = $1)`
	summary, err := store.queryObjects(ctx, `SELECT COUNT(*) AS total,
COUNT(*) FILTER (WHERE NOT blocked) AS allowed, COUNT(*) FILTER (WHERE blocked) AS blocked,
COUNT(*) FILTER (WHERE NOT blocked AND status_code >= 400) AS failed,
COUNT(*) FILTER (WHERE reason IN ('ip_rate','token_rate')) AS rate_limited,
COUNT(DISTINCT NULLIF(client_ip,'')) AS ip_count, COUNT(DISTINCT NULLIF(user_agent,'')) AS ua_count`+condition, userID)
	if err != nil {
		return nil, err
	}
	result := summary[0]
	for _, field := range []struct{ column, key string }{
		{"client_ip", "ips"}, {"user_agent", "uas"}, {"token_hash", "tokens"}, {"reason", "reasons"},
	} {
		items, err := store.queryObjects(ctx, `SELECT `+field.column+` AS value, COUNT(*) AS count`+condition+
			` AND `+field.column+` <> '' GROUP BY `+field.column+` ORDER BY count DESC, value LIMIT 100`, userID)
		if err != nil {
			return nil, err
		}
		result[field.key] = items
	}
	ips := result["ips"].([]map[string]any)
	events := make([]Event, len(ips))
	for index, item := range ips {
		events[index].IP, _ = item["value"].(string)
	}
	store.enrichEvents(ctx, events)
	for index := range ips {
		ips[index]["intelligence"] = events[index].Intelligence
	}
	result["dropped"] = store.dropped.Load()
	return result, nil
}

func (store *Store) Users(ctx context.Context, keyword, sort string, current, size int64) (map[string]any, error) {
	return store.users(ctx, keyword, sort, current, size, false)
}

func (store *Store) CrawlerUsers(ctx context.Context, current, size int64) (map[string]any, error) {
	return store.users(ctx, "", "count", current, size, true)
}

func (store *Store) users(ctx context.Context, keyword, sort string, current, size int64, crawlerOnly bool) (map[string]any, error) {
	if (sort != "count" && sort != "ip_count") || current < 1 || current > 100000 || size < 1 || size > 100 {
		return nil, errors.New("invalid user ranking parameters")
	}
	condition := ` FROM v2_subscribe_guard_event WHERE ($1 = '' OR STRPOS(LOWER(user_agent), LOWER($1)) > 0)`
	if crawlerOnly {
		condition += ` AND (crawler_ua OR reason = 'crawler_ua')`
	}
	var total, matched, unresolved int64
	err := store.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT user_id), COUNT(*), COUNT(*) FILTER (WHERE user_id IS NULL)`+condition, keyword).Scan(&total, &matched, &unresolved)
	if err != nil {
		return nil, err
	}
	items, err := store.queryObjects(ctx, `SELECT grouped.*, COALESCE(account.email,'') AS email, COALESCE(account.banned,0) AS banned,
COALESCE(account.is_admin,0) AS is_admin, COALESCE(account.is_staff,0) AS is_staff, account.id IS NULL AS deleted_user
FROM (SELECT user_id, COUNT(*) AS count, COUNT(*) FILTER (WHERE NOT blocked) AS allowed,
COUNT(*) FILTER (WHERE blocked) AS blocked, COUNT(DISTINCT NULLIF(client_ip,'')) AS ip_count,
COUNT(*) FILTER (WHERE reason='crawler_ua' AND blocked) AS crawler_blocked,
COUNT(*) FILTER (WHERE ua_whitelisted) AS whitelisted,
COUNT(DISTINCT NULLIF(user_agent,'')) AS ua_count, MAX(accessed_at) AS last_at`+condition+`
AND user_id IS NOT NULL GROUP BY user_id) grouped LEFT JOIN v2_user account ON account.id=grouped.user_id
ORDER BY `+sort+` DESC, count DESC, user_id LIMIT $2 OFFSET $3`, keyword, size, (current-1)*size)
	return map[string]any{"data": items, "total": total, "matched": matched, "unresolved": unresolved, "current": current, "page_size": size}, err
}
