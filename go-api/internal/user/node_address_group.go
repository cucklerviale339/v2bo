package user

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

type nodeAddressSelector struct {
	bindings map[string]int64
	rules    map[int64][]nodeAddressRule
}

type nodeAddressRule struct {
	GroupID      int64
	Host         string
	MatchUserIDs []string
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

	rows, err := s.db.QueryContext(ctx, `SELECT r.group_id, r.host, r.match_user_ids
FROM v2_node_address_rule r
JOIN v2_node_address_group g ON g.id = r.group_id
WHERE g.enabled = 1 AND r.enabled = 1
ORDER BY r.group_id ASC, r.sort ASC NULLS LAST, r.id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query node address rules: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var rule nodeAddressRule
		var matchUserIDs string
		if err := rows.Scan(
			&rule.GroupID,
			&rule.Host,
			&matchUserIDs,
		); err != nil {
			return nil, fmt.Errorf("scan node address rule: %w", err)
		}
		rule.Host = strings.TrimSpace(rule.Host)
		if rule.Host == "" {
			continue
		}
		rule.MatchUserIDs = parseServerStringList(matchUserIDs)
		selector.rules[rule.GroupID] = append(selector.rules[rule.GroupID], rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node address rules: %w", err)
	}

	bindingRows, err := s.db.QueryContext(ctx, `SELECT b.server_type, b.server_id, b.address_group_id
FROM v2_node_address_binding b
JOIN v2_node_address_group g ON g.id = b.address_group_id
WHERE g.enabled = 1
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

func (s *nodeAddressSelector) Resolve(serverType string, serverID int64, user serverFetchUser) (string, bool) {
	if s == nil {
		return "", false
	}
	groupID, ok := s.bindings[nodeAddressServerKey(serverType, serverID)]
	if !ok {
		return "", false
	}
	for _, rule := range s.rules[groupID] {
		if rule.matches(user) {
			return rule.Host, true
		}
	}
	return "", false
}

func (r nodeAddressRule) matches(user serverFetchUser) bool {
	hasCondition := false
	if len(r.MatchUserIDs) > 0 {
		hasCondition = true
		if !nodeAddressIntTokensMatch(r.MatchUserIDs, user.ID) {
			return false
		}
	}

	return hasCondition
}

func nodeAddressServerKey(serverType string, serverID int64) string {
	return fmt.Sprintf("%s-%d", strings.TrimSpace(serverType), serverID)
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
