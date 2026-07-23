package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type nodeAddressGroupRow struct {
	ID          int64
	Name        string
	Description string
	Enabled     int64
	CreatedAt   int64
	UpdatedAt   int64
}

type nodeAddressRuleRow struct {
	ID                int64
	GroupID           int64
	Name              string
	Host              string
	MatchUserIDs      string
	MatchUserIDRanges string
	Enabled           int64
	Sort              sql.NullInt64
	CreatedAt         int64
	UpdatedAt         int64
}

func (s *DBService) ListNodeAddressGroups(ctx context.Context, id *int64) ([]NodeAddressGroupRecord, error) {
	if s.db == nil {
		return nil, ErrUnavailable
	}
	if err := s.ensureNodeAddressSchema(ctx); err != nil {
		return nil, err
	}

	query := `SELECT id, name, description, enabled, created_at, updated_at
FROM v2_node_address_group`
	args := []any{}
	if id != nil {
		query += ` WHERE id = $1`
		args = append(args, *id)
	}
	query += ` ORDER BY id ASC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query node address groups: %w", err)
	}
	defer rows.Close()

	result := make([]NodeAddressGroupRecord, 0)
	ids := make([]int64, 0)
	for rows.Next() {
		row, err := scanNodeAddressGroupRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, nodeAddressGroupRecord(row))
		ids = append(ids, row.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node address groups: %w", err)
	}
	if len(ids) == 0 {
		return result, nil
	}

	rules, err := s.loadNodeAddressRules(ctx, ids)
	if err != nil {
		return nil, err
	}
	bindings, err := s.loadNodeAddressBindings(ctx, ids)
	if err != nil {
		return nil, err
	}
	for index := range result {
		result[index].Rules = rules[result[index].ID]
		result[index].Bindings = bindings[result[index].ID]
	}
	return result, nil
}

func (s *DBService) SaveNodeAddressGroup(ctx context.Context, req NodeAddressGroupSaveRequest) (bool, error) {
	if s.db == nil {
		return false, ErrUnavailable
	}
	if err := s.ensureNodeAddressSchema(ctx); err != nil {
		return false, err
	}

	normalized, err := normalizeNodeAddressGroupSaveRequest(req)
	if err != nil {
		return false, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, errors.New("保存失败")
	}
	defer tx.Rollback()

	now := time.Now().Unix()
	groupID := int64(0)
	enabled := int64(1)
	if normalized.Enabled != nil {
		enabled = *normalized.Enabled
	}
	if normalized.ID == nil {
		if err := tx.QueryRowContext(ctx, `INSERT INTO v2_node_address_group (name, description, enabled, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING id`, normalized.Name, normalized.Description, enabled, now, now).Scan(&groupID); err != nil {
			return false, errors.New("创建失败")
		}
	} else {
		groupID = *normalized.ID
		result, err := tx.ExecContext(ctx, `UPDATE v2_node_address_group
SET name = $2, description = $3, enabled = $4, updated_at = $5
WHERE id = $1`, groupID, normalized.Name, normalized.Description, enabled, now)
		if err != nil {
			return false, errors.New("保存失败")
		}
		affected, err := result.RowsAffected()
		if err != nil || affected == 0 {
			return false, errors.New("地址组不存在")
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM v2_node_address_rule WHERE group_id = $1`, groupID); err != nil {
			return false, errors.New("保存失败")
		}
	}

	for index, rule := range normalized.Rules {
		sortValue := rule.Sort
		if sortValue == nil {
			next := int64(index)
			sortValue = &next
		}
		ruleEnabled := int64(1)
		if rule.Enabled != nil {
			ruleEnabled = *rule.Enabled
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO v2_node_address_rule (
group_id, name, host, match_user_ids, match_user_id_ranges, enabled, sort, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			groupID,
			rule.Name,
			rule.Host,
			encodeNodeAddressStringList(rule.MatchUserIDs),
			encodeNodeAddressStringList(rule.MatchUserIDRanges),
			ruleEnabled,
			nullableInt64(sortValue),
			now,
			now,
		); err != nil {
			return false, errors.New("保存失败")
		}
	}

	if err := tx.Commit(); err != nil {
		return false, errors.New("保存失败")
	}
	return true, nil
}

func (s *DBService) DeleteNodeAddressGroup(ctx context.Context, id int64) (bool, error) {
	if s.db == nil {
		return false, ErrUnavailable
	}
	if err := s.ensureNodeAddressSchema(ctx); err != nil {
		return false, err
	}
	if id <= 0 {
		return false, errors.New("地址组不存在")
	}

	var used int64
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM v2_node_address_binding WHERE address_group_id = $1 LIMIT 1`, id).Scan(&used)
	if err == nil {
		return false, errors.New("地址组已被节点使用，无法删除")
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("query node address group usage: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, errors.New("删除失败")
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM v2_node_address_rule WHERE group_id = $1`, id); err != nil {
		return false, errors.New("删除失败")
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM v2_node_address_group WHERE id = $1`, id)
	if err != nil {
		return false, errors.New("删除失败")
	}
	affected, err := result.RowsAffected()
	if err != nil || affected == 0 {
		return false, errors.New("地址组不存在")
	}
	if err := tx.Commit(); err != nil {
		return false, errors.New("删除失败")
	}
	return true, nil
}

func (s *DBService) replaceManagedServerAddressGroup(ctx context.Context, serverType string, serverID int64, addressGroupID any, now int64) error {
	if err := s.ensureNodeAddressSchema(ctx); err != nil {
		return err
	}
	serverType = strings.TrimSpace(serverType)
	if _, ok := managedServerDefinitions[serverType]; !ok || serverID <= 0 {
		return errors.New("invalid managed server")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM v2_node_address_binding WHERE server_type = $1 AND server_id = $2`, serverType, serverID); err != nil {
		return err
	}

	if addressGroupID != nil {
		groupID, ok := addressGroupID.(int64)
		if !ok || groupID <= 0 {
			return errors.New("invalid address group id")
		}
		var exists int64
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM v2_node_address_group WHERE id = $1 LIMIT 1`, groupID).Scan(&exists); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO v2_node_address_binding (address_group_id, server_type, server_id, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5)`, groupID, serverType, serverID, now, now); err != nil {
			return err
		}
	}

	return tx.Commit()
}

type managedServerAddressBinding struct {
	GroupID   int64
	GroupName string
}

func managedServerAddressBindingKey(serverType string, serverID int64) string {
	return fmt.Sprintf("%s-%d", strings.TrimSpace(serverType), serverID)
}

func (s *DBService) managedServerAddressBindings(ctx context.Context) (map[string]managedServerAddressBinding, error) {
	result := make(map[string]managedServerAddressBinding)
	if err := s.ensureNodeAddressSchema(ctx); err != nil {
		return result, err
	}

	rows, err := s.db.QueryContext(ctx, `SELECT b.server_type, b.server_id, g.id, g.name
FROM v2_node_address_binding b
JOIN v2_node_address_group g ON g.id = b.address_group_id
ORDER BY b.server_type ASC, b.server_id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query managed server address bindings: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var serverType string
		var serverID int64
		var binding managedServerAddressBinding
		if err := rows.Scan(&serverType, &serverID, &binding.GroupID, &binding.GroupName); err != nil {
			return nil, fmt.Errorf("scan managed server address binding: %w", err)
		}
		result[managedServerAddressBindingKey(serverType, serverID)] = binding
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate managed server address bindings: %w", err)
	}
	return result, nil
}

func (s *DBService) loadNodeAddressRules(ctx context.Context, ids []int64) (map[int64][]NodeAddressRuleRecord, error) {
	result := make(map[int64][]NodeAddressRuleRecord, len(ids))
	if len(ids) == 0 {
		return result, nil
	}
	query, args := buildInt64InQuery(`SELECT id, group_id, name, host, match_user_ids, match_user_id_ranges, enabled, sort, created_at, updated_at
FROM v2_node_address_rule
WHERE group_id IN (%s)
ORDER BY group_id ASC, sort ASC NULLS LAST, id ASC`, ids)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query node address rules: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		row, err := scanNodeAddressRuleRow(rows)
		if err != nil {
			return nil, err
		}
		result[row.GroupID] = append(result[row.GroupID], nodeAddressRuleRecord(row))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node address rules: %w", err)
	}
	return result, nil
}

func (s *DBService) loadNodeAddressBindings(ctx context.Context, ids []int64) (map[int64][]NodeAddressBindingRecord, error) {
	result := make(map[int64][]NodeAddressBindingRecord, len(ids))
	if len(ids) == 0 {
		return result, nil
	}
	query, args := buildInt64InQuery(`SELECT address_group_id, server_type, server_id
FROM v2_node_address_binding
WHERE address_group_id IN (%s)
ORDER BY address_group_id ASC, server_type ASC, server_id ASC`, ids)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query node address bindings: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var groupID int64
		var record NodeAddressBindingRecord
		if err := rows.Scan(&groupID, &record.ServerType, &record.ServerID); err != nil {
			return nil, fmt.Errorf("scan node address binding: %w", err)
		}
		result[groupID] = append(result[groupID], record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node address bindings: %w", err)
	}
	return result, nil
}

func normalizeNodeAddressGroupSaveRequest(req NodeAddressGroupSaveRequest) (NodeAddressGroupSaveRequest, error) {
	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	if req.Name == "" {
		return req, errors.New("地址组名称不能为空")
	}
	if req.Enabled != nil && (*req.Enabled < 0 || *req.Enabled > 1) {
		return req, errors.New("启用状态格式不正确")
	}
	var err error
	for index := range req.Rules {
		rule := &req.Rules[index]
		rule.Name = strings.TrimSpace(rule.Name)
		rule.Host = strings.TrimSpace(rule.Host)
		if rule.Host == "" {
			return req, errors.New("规则地址不能为空")
		}
		rule.MatchUserIDs, err = normalizeNodeAddressUserIDs(rule.MatchUserIDs)
		if err != nil {
			return req, err
		}
		rule.MatchUserIDRanges, err = normalizeNodeAddressUserIDRanges(rule.MatchUserIDRanges)
		if err != nil {
			return req, err
		}
		if rule.Enabled != nil && (*rule.Enabled < 0 || *rule.Enabled > 1) {
			return req, errors.New("规则启用状态格式不正确")
		}
		if !nodeAddressRuleHasCondition(*rule) {
			return req, errors.New("地址规则至少需要一个匹配条件")
		}
	}
	return req, nil
}

func scanNodeAddressGroupRow(scanner interface{ Scan(...any) error }) (nodeAddressGroupRow, error) {
	var row nodeAddressGroupRow
	if err := scanner.Scan(&row.ID, &row.Name, &row.Description, &row.Enabled, &row.CreatedAt, &row.UpdatedAt); err != nil {
		return nodeAddressGroupRow{}, fmt.Errorf("scan node address group: %w", err)
	}
	return row, nil
}

func scanNodeAddressRuleRow(scanner interface{ Scan(...any) error }) (nodeAddressRuleRow, error) {
	var row nodeAddressRuleRow
	if err := scanner.Scan(
		&row.ID,
		&row.GroupID,
		&row.Name,
		&row.Host,
		&row.MatchUserIDs,
		&row.MatchUserIDRanges,
		&row.Enabled,
		&row.Sort,
		&row.CreatedAt,
		&row.UpdatedAt,
	); err != nil {
		return nodeAddressRuleRow{}, fmt.Errorf("scan node address rule: %w", err)
	}
	return row, nil
}

func nodeAddressGroupRecord(row nodeAddressGroupRow) NodeAddressGroupRecord {
	return NodeAddressGroupRecord{
		ID:          row.ID,
		Name:        row.Name,
		Description: row.Description,
		Enabled:     row.Enabled,
		Rules:       []NodeAddressRuleRecord{},
		Bindings:    []NodeAddressBindingRecord{},
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}
}

func nodeAddressRuleRecord(row nodeAddressRuleRow) NodeAddressRuleRecord {
	return NodeAddressRuleRecord{
		ID:                row.ID,
		GroupID:           row.GroupID,
		Name:              row.Name,
		Host:              row.Host,
		MatchUserIDs:      parseServerStringList(row.MatchUserIDs),
		MatchUserIDRanges: parseServerStringList(row.MatchUserIDRanges),
		Enabled:           row.Enabled,
		Sort:              nullInt64Ptr(row.Sort),
		CreatedAt:         row.CreatedAt,
		UpdatedAt:         row.UpdatedAt,
	}
}

func nodeAddressRuleHasCondition(rule NodeAddressRuleSaveRequest) bool {
	return len(rule.MatchUserIDs) > 0 || len(rule.MatchUserIDRanges) > 0
}

func normalizeNodeAddressUserIDs(values []string) ([]string, error) {
	items := normalizeNodeAddressStringList(values)
	result := make([]string, 0, len(items))
	seen := make(map[int64]struct{}, len(items))
	for _, item := range items {
		id, err := strconv.ParseInt(item, 10, 64)
		if err != nil || id <= 0 {
			return nil, errors.New("用户ID必须是正整数")
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, strconv.FormatInt(id, 10))
	}
	return result, nil
}

func normalizeNodeAddressUserIDRanges(values []string) ([]string, error) {
	items := normalizeNodeAddressStringList(values)
	result := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		parts := strings.Split(item, "-")
		if len(parts) != 2 {
			return nil, errors.New("用户ID范围格式应为起始ID-结束ID")
		}
		start, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
		if err != nil || start <= 0 {
			return nil, errors.New("用户ID范围必须使用正整数")
		}
		end, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
		if err != nil || end <= 0 {
			return nil, errors.New("用户ID范围必须使用正整数")
		}
		if end < start {
			start, end = end, start
		}
		next := fmt.Sprintf("%d-%d", start, end)
		if _, exists := seen[next]; exists {
			continue
		}
		seen[next] = struct{}{}
		result = append(result, next)
	}
	return result, nil
}

func normalizeNodeAddressStringList(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			next := strings.TrimSpace(item)
			if next == "" {
				continue
			}
			if _, exists := seen[next]; exists {
				continue
			}
			seen[next] = struct{}{}
			result = append(result, next)
		}
	}
	return result
}

func encodeNodeAddressStringList(values []string) string {
	raw, err := json.Marshal(normalizeNodeAddressStringList(values))
	if err != nil {
		return "[]"
	}
	return string(raw)
}
