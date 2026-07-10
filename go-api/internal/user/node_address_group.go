package user

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
)

type nodeAddressSelector struct {
	bindings map[string]int64
	rules    map[int64][]nodeAddressRule
}

type nodeAddressRule struct {
	GroupID           int64
	Host              string
	MatchUserIDs      []string
	MatchPlanIDs      []string
	MatchGroupIDs     []string
	MatchUAKeywords   []string
	ExcludeUAKeywords []string
	NoUA              bool
	MinRegisteredDays *int64
	MaxRegisteredDays *int64
}

func (s *DBService) loadNodeAddressSelector(ctx context.Context) (*nodeAddressSelector, error) {
	if s.db == nil {
		return nil, ErrUnavailable
	}
	if err := s.ensureNodeAddressSchema(ctx); err != nil {
		return nil, err
	}

	selector := &nodeAddressSelector{
		bindings: make(map[string]int64),
		rules:    make(map[int64][]nodeAddressRule),
	}

	rows, err := s.db.QueryContext(ctx, `SELECT r.group_id, r.host, r.match_user_ids, r.match_plan_ids, r.match_group_ids,
r.match_ua_keywords, r.exclude_ua_keywords, r.no_ua, r.min_registered_days, r.max_registered_days
FROM v2_node_address_rule r
JOIN v2_node_address_group g ON g.id = r.group_id
WHERE g."show" = 1 AND r."show" = 1
ORDER BY r.group_id ASC, r.sort ASC NULLS LAST, r.id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query node address rules: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var rule nodeAddressRule
		var matchUserIDs string
		var matchPlanIDs string
		var matchGroupIDs string
		var matchUAKeywords string
		var excludeUAKeywords string
		var noUA int64
		var minRegisteredDays sql.NullInt64
		var maxRegisteredDays sql.NullInt64
		if err := rows.Scan(
			&rule.GroupID,
			&rule.Host,
			&matchUserIDs,
			&matchPlanIDs,
			&matchGroupIDs,
			&matchUAKeywords,
			&excludeUAKeywords,
			&noUA,
			&minRegisteredDays,
			&maxRegisteredDays,
		); err != nil {
			return nil, fmt.Errorf("scan node address rule: %w", err)
		}
		rule.Host = strings.TrimSpace(rule.Host)
		if rule.Host == "" {
			continue
		}
		rule.MatchUserIDs = parseServerStringList(matchUserIDs)
		rule.MatchPlanIDs = parseServerStringList(matchPlanIDs)
		rule.MatchGroupIDs = parseServerStringList(matchGroupIDs)
		rule.MatchUAKeywords = parseServerStringList(matchUAKeywords)
		rule.ExcludeUAKeywords = parseServerStringList(excludeUAKeywords)
		rule.NoUA = noUA != 0
		rule.MinRegisteredDays = nodeAddressNullInt64Ptr(minRegisteredDays)
		rule.MaxRegisteredDays = nodeAddressNullInt64Ptr(maxRegisteredDays)
		selector.rules[rule.GroupID] = append(selector.rules[rule.GroupID], rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node address rules: %w", err)
	}

	bindingRows, err := s.db.QueryContext(ctx, `SELECT b.server_type, b.server_id, b.address_group_id
FROM v2_node_address_binding b
JOIN v2_node_address_group g ON g.id = b.address_group_id
WHERE g."show" = 1
ORDER BY b.server_type ASC, b.server_id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query node address bindings: %w", err)
	}
	defer bindingRows.Close()

	for bindingRows.Next() {
		var serverType string
		var serverID int64
		var groupID int64
		if err := bindingRows.Scan(&serverType, &serverID, &groupID); err != nil {
			return nil, fmt.Errorf("scan node address binding: %w", err)
		}
		if serverID > 0 && groupID > 0 {
			selector.bindings[nodeAddressServerKey(serverType, serverID)] = groupID
		}
	}
	if err := bindingRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node address bindings: %w", err)
	}

	return selector, nil
}

func (s *nodeAddressSelector) Resolve(serverType string, serverID int64, user serverFetchUser, ua string, now int64) (string, bool) {
	if s == nil {
		return "", false
	}
	groupID, ok := s.bindings[nodeAddressServerKey(serverType, serverID)]
	if !ok {
		return "", false
	}
	for _, rule := range s.rules[groupID] {
		if rule.matches(user, ua, now) {
			return rule.Host, true
		}
	}
	return "", false
}

func (r nodeAddressRule) matches(user serverFetchUser, ua string, now int64) bool {
	hasCondition := false
	if len(r.MatchUserIDs) > 0 {
		hasCondition = true
		if !nodeAddressIntTokensMatch(r.MatchUserIDs, user.ID) {
			return false
		}
	}
	if len(r.MatchPlanIDs) > 0 {
		hasCondition = true
		if !nodeAddressIntTokensMatch(r.MatchPlanIDs, user.PlanID) {
			return false
		}
	}
	if len(r.MatchGroupIDs) > 0 {
		hasCondition = true
		if !nodeAddressIntTokensMatch(r.MatchGroupIDs, user.GroupID) {
			return false
		}
	}
	if len(r.MatchUAKeywords) > 0 {
		hasCondition = true
		if !nodeAddressUAAnyMatch(r.MatchUAKeywords, ua) {
			return false
		}
	}
	if len(r.ExcludeUAKeywords) > 0 {
		hasCondition = true
		if nodeAddressUAAnyMatch(r.ExcludeUAKeywords, ua) {
			return false
		}
	}
	if r.NoUA {
		hasCondition = true
		if strings.TrimSpace(ua) != "" {
			return false
		}
	}
	if r.MinRegisteredDays != nil || r.MaxRegisteredDays != nil {
		hasCondition = true
		if user.CreatedAt <= 0 || now < user.CreatedAt {
			return false
		}
		days := (now - user.CreatedAt) / 86400
		if r.MinRegisteredDays != nil && days < *r.MinRegisteredDays {
			return false
		}
		if r.MaxRegisteredDays != nil && days > *r.MaxRegisteredDays {
			return false
		}
	}

	return hasCondition
}

func nodeAddressServerKey(serverType string, serverID int64) string {
	return fmt.Sprintf("%s-%d", strings.TrimSpace(serverType), serverID)
}

func nodeAddressNullInt64Ptr(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	next := value.Int64
	return &next
}

func nodeAddressIntTokensMatch(tokens []string, value int64) bool {
	if value <= 0 {
		return false
	}
	for _, token := range tokens {
		for _, part := range strings.Split(token, ",") {
			if nodeAddressIntTokenMatch(strings.TrimSpace(part), value) {
				return true
			}
		}
	}
	return false
}

func nodeAddressIntTokenMatch(token string, value int64) bool {
	token = strings.TrimSpace(strings.Trim(token, `"'`))
	if token == "" {
		return false
	}
	if strings.Contains(token, "-") {
		parts := strings.SplitN(token, "-", 2)
		if len(parts) != 2 {
			return false
		}
		start, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
		if err != nil {
			return false
		}
		end, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
		if err != nil {
			return false
		}
		if end < start {
			start, end = end, start
		}
		return value >= start && value <= end
	}
	next, err := strconv.ParseInt(token, 10, 64)
	return err == nil && next == value
}

func nodeAddressUAAnyMatch(keywords []string, ua string) bool {
	ua = strings.TrimSpace(ua)
	lowerUA := strings.ToLower(ua)
	for _, raw := range keywords {
		for _, keyword := range strings.Split(raw, "|") {
			keyword = strings.TrimSpace(keyword)
			if keyword == "" {
				continue
			}
			if serverFetchMissingUAKeyword(keyword) {
				if ua == "" {
					return true
				}
				continue
			}
			if ua != "" && strings.Contains(lowerUA, strings.ToLower(keyword)) {
				return true
			}
		}
	}
	return false
}
