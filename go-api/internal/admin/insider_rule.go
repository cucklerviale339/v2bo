package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"forest/go-api/internal/subscribelink"
)

func (s *DBService) ListInsiderRules(ctx context.Context) ([]InsiderRuleRecord, error) {
	if err := s.ensureNodeAddressSchema(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, match_user_ids, match_user_id_ranges, host, extra_nodes, extra_nodes_position, enabled, created_at, updated_at FROM v2_insider_rule ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query insider rules: %w", err)
	}
	defer rows.Close()
	result := make([]InsiderRuleRecord, 0)
	for rows.Next() {
		var item InsiderRuleRecord
		var ids, ranges, extrasRaw string
		if err := rows.Scan(&item.ID, &item.Name, &ids, &ranges, &item.Host, &extrasRaw, &item.ExtraNodesPosition, &item.Enabled, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		item.MatchUserIDs = parseAdminStringList(ids)
		item.MatchUserIDRanges = parseAdminStringList(ranges)
		item.Members = []InsiderRuleMember{}
		item.ExtraNodes, err = subscribelink.DecodeList(extrasRaw)
		if err != nil {
			return nil, err
		}
		item.ExtraNodesPosition, err = subscribelink.NormalizePosition(item.ExtraNodesPosition)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *DBService) SaveInsiderRule(ctx context.Context, req InsiderRuleSaveRequest) (bool, error) {
	var err error
	req, err = normalizeInsiderRuleSaveRequest(req)
	if err != nil {
		return false, err
	}
	if err := s.ensureNodeAddressSchema(ctx); err != nil {
		return false, err
	}
	membersRaw, _ := json.Marshal(req.Members)
	extrasRaw, err := subscribelink.EncodeList(req.ExtraNodes)
	if err != nil {
		return false, err
	}
	enabled := int64(1)
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	now := time.Now().Unix()
	if req.ID == nil {
		_, err = s.db.ExecContext(ctx, `INSERT INTO v2_insider_rule (name, match_user_ids, match_user_id_ranges, members, host, extra_nodes, extra_nodes_position, enabled, sort, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10)`, req.Name, encodeNodeAddressStringList(req.MatchUserIDs), encodeNodeAddressStringList(req.MatchUserIDRanges), string(membersRaw), req.Host, extrasRaw, req.ExtraNodesPosition, enabled, nullableInt64(req.Sort), now)
	} else {
		result, execErr := s.db.ExecContext(ctx, `UPDATE v2_insider_rule SET name=$2, match_user_ids=$3, match_user_id_ranges=$4, members=$5, host=$6, extra_nodes=$7, extra_nodes_position=$8, enabled=$9, sort=$10, updated_at=$11 WHERE id=$1`, *req.ID, req.Name, encodeNodeAddressStringList(req.MatchUserIDs), encodeNodeAddressStringList(req.MatchUserIDRanges), string(membersRaw), req.Host, extrasRaw, req.ExtraNodesPosition, enabled, nullableInt64(req.Sort), now)
		err = execErr
		if err == nil {
			affected, _ := result.RowsAffected()
			if affected == 0 {
				return false, errors.New("内鬼规则不存在")
			}
		}
	}
	if err != nil {
		return false, fmt.Errorf("save insider rule: %w", err)
	}
	return true, nil
}

const maxInsiderRuleMatches = 5000

func normalizeInsiderRuleSaveRequest(req InsiderRuleSaveRequest) (InsiderRuleSaveRequest, error) {
	req.Name = strings.TrimSpace(req.Name)
	req.Host = strings.TrimSpace(req.Host)
	if req.ID != nil && *req.ID <= 0 {
		return req, invalidInsiderRuleError("内鬼规则不存在")
	}
	if req.Name == "" {
		return req, invalidInsiderRuleError("规则名称不能为空")
	}
	if utf8.RuneCountInString(req.Name) > 255 {
		return req, invalidInsiderRuleError("规则名称不能超过255个字符")
	}
	if utf8.RuneCountInString(req.Host) > 255 {
		return req, invalidInsiderRuleError("节点下发地址不能超过255个字符")
	}
	if strings.ContainsAny(req.Host, ",()/?#@ \t\r\n") {
		return req, invalidInsiderRuleError("节点下发地址格式不正确")
	}
	var err error
	req.MatchUserIDs, err = normalizeNodeAddressUserIDs(req.MatchUserIDs)
	if err != nil {
		return req, invalidInsiderRuleError(err.Error())
	}
	req.MatchUserIDRanges, err = normalizeNodeAddressUserIDRanges(req.MatchUserIDRanges)
	if err != nil {
		return req, invalidInsiderRuleError(err.Error())
	}
	if len(req.MatchUserIDs) == 0 && len(req.MatchUserIDRanges) == 0 {
		return req, invalidInsiderRuleError("指定用户和 ID 范围至少填写一个")
	}
	if len(req.MatchUserIDs)+len(req.MatchUserIDRanges) > maxInsiderRuleMatches {
		return req, invalidInsiderRuleError("指定用户和 ID 范围合计不能超过5000项")
	}
	req.Members = []InsiderRuleMember{}
	req.Sort = nil
	req.ExtraNodes, err = subscribelink.NormalizeList(req.ExtraNodes)
	if err != nil {
		return req, invalidInsiderRuleError(err.Error())
	}
	req.ExtraNodesPosition, err = subscribelink.NormalizePosition(req.ExtraNodesPosition)
	if err != nil {
		return req, invalidInsiderRuleError(err.Error())
	}
	if req.Host == "" && len(req.ExtraNodes) == 0 {
		return req, invalidInsiderRuleError("节点下发地址和额外节点至少填写一个")
	}
	if req.Enabled != nil && *req.Enabled != 0 && *req.Enabled != 1 {
		return req, invalidInsiderRuleError("状态只能是启用或停用")
	}
	return req, nil
}

func invalidInsiderRuleError(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidInsiderRule, message)
}

func (s *DBService) DeleteInsiderRule(ctx context.Context, id int64) (bool, error) {
	if err := s.ensureNodeAddressSchema(ctx); err != nil {
		return false, err
	}
	if id <= 0 {
		return false, errors.New("内鬼规则不存在")
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM v2_insider_rule WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return false, errors.New("内鬼规则不存在")
	}
	return true, nil
}

func parseAdminStringList(raw string) []string {
	var values []string
	if json.Unmarshal([]byte(raw), &values) == nil {
		return values
	}
	return []string{}
}
