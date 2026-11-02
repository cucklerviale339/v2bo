package user

import (
	"context"
	"fmt"
	"strings"

	"forest/go-api/internal/subscribelink"
)

type insiderRule struct {
	nodeAddressRule
}
type insiderSelector struct{ rules []insiderRule }

func (s *DBService) loadInsiderSelector(ctx context.Context) (*insiderSelector, error) {
	if err := s.ensureNodeAddressSchema(ctx); err != nil {
		return nil, err
	}
	return loadInsiderSelectorFrom(ctx, s.db)
}

func loadInsiderSelectorFrom(ctx context.Context, q DispatchQueryer) (*insiderSelector, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, match_user_ids, match_user_id_ranges, host, extra_nodes, extra_nodes_position FROM v2_insider_rule WHERE enabled=1 ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query insider rules: %w", err)
	}
	defer rows.Close()
	selector := &insiderSelector{rules: make([]insiderRule, 0)}
	for rows.Next() {
		var rule insiderRule
		var ids, ranges, extrasRaw string
		if err := rows.Scan(&rule.ID, &ids, &ranges, &rule.Host, &extrasRaw, &rule.ExtraNodesPosition); err != nil {
			return nil, err
		}
		rule.Host = strings.TrimSpace(rule.Host)
		rule.MatchUserIDs = parseServerStringList(ids)
		rule.MatchUserIDRanges = parseServerStringList(ranges)
		rule.ExtraNodes, err = subscribelink.DecodeList(extrasRaw)
		if err != nil {
			return nil, err
		}
		rule.ExtraNodesPosition, err = subscribelink.NormalizePosition(rule.ExtraNodesPosition)
		if err != nil {
			return nil, err
		}
		rule.ExtraNodeSource = "insider"
		selector.rules = append(selector.rules, rule)
	}
	return selector, rows.Err()
}

func (s *insiderSelector) Resolve(userID int64) (nodeAddressRule, bool) {
	if s == nil {
		return nodeAddressRule{}, false
	}
	for _, rule := range s.rules {
		if rule.matchesExplicitUserID(userID) {
			return rule.nodeAddressRule, true
		}
	}
	for _, rule := range s.rules {
		if rule.matchesUserIDRange(userID) {
			return rule.nodeAddressRule, true
		}
	}
	return nodeAddressRule{}, false
}

func applyInsiderSelection(item map[string]any, selector *insiderSelector, userID int64) (*nodeAddressRule, bool, bool) {
	rule, matched := selector.Resolve(userID)
	if !matched {
		return nil, true, false
	}
	if rule.Host != "" {
		item["host"] = AddressGroupHost(rule.Host)
	}
	if len(rule.ExtraNodes) == 0 {
		return nil, true, true
	}
	return &rule, rule.ExtraNodesPosition == subscribelink.PositionBefore, true
}
