package admin

import (
	"context"
	"encoding/json"

	usersvc "forest/go-api/internal/user"
)

// Monitoring uses current recipients, while the configured-ID catalog must keep
// absent IDs for subscription rules, ownership validation and future accounts.
// Resolve the final address precedence first, then check account existence in
// one query. Do not use plan, permission, traffic or account-status eligibility.
func (s *DBService) dispatchMonitorEntries(ctx context.Context) ([]usersvc.DispatchEntry, error) {
	entries, err := s.dispatchEntries(ctx)
	if err != nil {
		return entries, err
	}
	return s.dispatchEntriesWithRecipients(ctx, entries)
}

func (s *DBService) dispatchEntriesWithRecipients(ctx context.Context, entries []usersvc.DispatchEntry) ([]usersvc.DispatchEntry, error) {
	if len(entries) == 0 {
		return entries, nil
	}
	type scope struct {
		Host string `json:"host"`
		A    int64  `json:"a"`
		B    int64  `json:"b"`
	}
	scopes := []scope{}
	for _, entry := range entries {
		for _, span := range splitEntrySpans(entry) {
			scopes = append(scopes, scope{Host: entry.Host, A: span.a, B: span.b})
		}
	}
	raw, err := json.Marshal(scopes)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT scope.host FROM jsonb_to_recordset($1::jsonb) scope(host text,a bigint,b bigint)
WHERE EXISTS(SELECT 1 FROM v2_user u WHERE u.id BETWEEN scope.a AND scope.b)`, string(raw))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	active := map[string]bool{}
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err != nil {
			return nil, err
		}
		active[host] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result := make([]usersvc.DispatchEntry, 0, len(active))
	for _, entry := range entries {
		if active[entry.Host] {
			result = append(result, entry)
		}
	}
	return result, nil
}
