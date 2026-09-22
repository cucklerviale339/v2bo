package user

import (
	"context"
	"fmt"
	"strings"

	"forest/go-api/internal/platform/userselector"
	"forest/go-api/internal/subscribelink"
)

type AddressGroupHost string

type nodeAddressSelector struct {
	bindings map[string]int64
	rules    map[int64][]nodeAddressRule
}

type nodeAddressRule struct {
	ID                 int64
	GroupID            int64
	Host               string
	MatchUserIDs       []string
	MatchUserIDRanges  []string
	ExtraNodes         []string
	ExtraNodesPosition string
	ExtraNodeSource    string
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

	rows, err := s.db.QueryContext(ctx, `SELECT r.id, r.group_id, r.host, r.match_user_ids, r.match_user_id_ranges, r.extra_nodes, r.extra_nodes_position
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
		var matchUserIDRanges string
		var extraNodesRaw string
		if err := rows.Scan(
			&rule.ID,
			&rule.GroupID,
			&rule.Host,
			&matchUserIDs,
			&matchUserIDRanges,
			&extraNodesRaw,
			&rule.ExtraNodesPosition,
		); err != nil {
			return nil, fmt.Errorf("scan node address rule: %w", err)
		}
		rule.Host = strings.TrimSpace(rule.Host)
		rule.MatchUserIDs = parseServerStringList(matchUserIDs)
		rule.MatchUserIDRanges = parseServerStringList(matchUserIDRanges)
		rule.ExtraNodes, err = subscribelink.DecodeList(extraNodesRaw)
		if err != nil {
			return nil, fmt.Errorf("decode node address rule %d extra nodes: %w", rule.ID, err)
		}
		rule.ExtraNodesPosition, err = subscribelink.NormalizePosition(rule.ExtraNodesPosition)
		if err != nil {
			return nil, fmt.Errorf("decode node address rule %d extra node position: %w", rule.ID, err)
		}
		if rule.Host == "" && len(rule.ExtraNodes) == 0 {
			continue
		}
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
	rule, ok := s.ResolveRule(serverType, serverID, user)
	if !ok {
		return "", false
	}
	return rule.Host, true
}

func (s *nodeAddressSelector) ResolveRule(serverType string, serverID int64, user serverFetchUser) (nodeAddressRule, bool) {
	if s == nil {
		return nodeAddressRule{}, false
	}
	groupID, ok := s.bindings[nodeAddressServerKey(serverType, serverID)]
	if !ok {
		return nodeAddressRule{}, false
	}
	for _, rule := range s.rules[groupID] {
		if rule.matchesExplicitUserID(user.ID) {
			return rule, true
		}
	}
	for _, rule := range s.rules[groupID] {
		if rule.matchesUserIDRange(user.ID) {
			return rule, true
		}
	}
	return nodeAddressRule{}, false
}

func (r nodeAddressRule) matches(user serverFetchUser) bool {
	return r.matchesExplicitUserID(user.ID) || r.matchesUserIDRange(user.ID)
}

func (r nodeAddressRule) matchesExplicitUserID(userID int64) bool {
	return nodeAddressExactIDTokensMatch(r.MatchUserIDs, userID)
}

func (r nodeAddressRule) matchesUserIDRange(userID int64) bool {
	return nodeAddressIDRangeTokensMatch(r.MatchUserIDRanges, userID)
}

func nodeAddressServerKey(serverType string, serverID int64) string {
	return fmt.Sprintf("%s-%d", strings.TrimSpace(serverType), serverID)
}

func nodeAddressExactIDTokensMatch(tokens []string, value int64) bool {
	return userselector.MatchesIDs(tokens, value)
}

func nodeAddressIDRangeTokensMatch(tokens []string, value int64) bool {
	return userselector.MatchesRanges(tokens, value)
}

func parseNodeAddressIDRange(token string) (int64, int64, bool) {
	return userselector.ParseRange(token)
}
