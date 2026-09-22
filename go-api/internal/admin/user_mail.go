package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"forest/go-api/internal/platform/userselector"
)

type UserMailPreview struct {
	Total       int64 `json:"total"`
	Excluded    int64 `json:"excluded"`
	Unavailable int64 `json:"unavailable"`
	Eligible    int64 `json:"eligible"`
}

type UserMailPreviewer interface {
	PreviewUserMail(context.Context, UserMailRequest) (UserMailPreview, error)
}

type bulkMailRecipient struct {
	ID    int64
	Email string
}

func (s *DBService) loadBulkMailExclusions(ctx context.Context) (*userselector.Matcher, error) {
	if err := s.ensureNodeAddressSchema(ctx); err != nil {
		return nil, fmt.Errorf("无法读取内鬼名单，已停止群发: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT match_user_ids, match_user_id_ranges FROM v2_insider_rule ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("无法读取内鬼名单，已停止群发: %w", err)
	}
	defer rows.Close()
	var ids, ranges []string
	for rows.Next() {
		var idsRaw, rangesRaw string
		if err := rows.Scan(&idsRaw, &rangesRaw); err != nil {
			return nil, fmt.Errorf("无法读取内鬼名单，已停止群发: %w", err)
		}
		var ruleIDs, ruleRanges []string
		if json.Unmarshal([]byte(idsRaw), &ruleIDs) != nil || json.Unmarshal([]byte(rangesRaw), &ruleRanges) != nil || ruleIDs == nil || ruleRanges == nil || len(ruleIDs)+len(ruleRanges) == 0 {
			return nil, errors.New("内鬼名单格式异常，请修复规则后再群发")
		}
		ids = append(ids, ruleIDs...)
		ranges = append(ranges, ruleRanges...)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("无法读取内鬼名单，已停止群发: %w", err)
	}
	matcher, err := userselector.Compile(ids, ranges)
	if err != nil {
		return nil, errors.New("内鬼名单包含无效用户 ID 或范围，请修复规则后再群发")
	}
	return matcher, nil
}

func (s *DBService) selectBulkMailRecipients(ctx context.Context, req UserMailRequest) ([]bulkMailRecipient, UserMailPreview, error) {
	var preview UserMailPreview
	exclusions, err := s.loadBulkMailExclusions(ctx)
	if err != nil {
		return nil, preview, err
	}
	whereClause, args, err := s.buildUserWhere(ctx, req.Filters)
	if err != nil {
		return nil, preview, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT u.id, u.email FROM v2_user u`+whereClause+` ORDER BY `+sanitizeUserSort(req.Sort)+` `+sanitizeAdminSortType(req.SortType), args...)
	if err != nil {
		return nil, preview, fmt.Errorf("query admin mail users: %w", err)
	}
	defer rows.Close()
	recipients := make([]bulkMailRecipient, 0)
	for rows.Next() {
		var recipient bulkMailRecipient
		if err := rows.Scan(&recipient.ID, &recipient.Email); err != nil {
			return nil, preview, fmt.Errorf("scan admin mail user: %w", err)
		}
		preview.Total++
		if exclusions.Matches(recipient.ID) {
			preview.Excluded++
			continue
		}
		recipient.Email = strings.TrimSpace(recipient.Email)
		if recipient.ID <= 0 || recipient.Email == "" {
			preview.Unavailable++
			continue
		}
		recipients = append(recipients, recipient)
		preview.Eligible++
	}
	if err := rows.Err(); err != nil {
		return nil, preview, fmt.Errorf("iterate admin mail users: %w", err)
	}
	return recipients, preview, nil
}

func (s *DBService) PreviewUserMail(ctx context.Context, req UserMailRequest) (UserMailPreview, error) {
	_, preview, err := s.selectBulkMailRecipients(ctx, req)
	return preview, err
}

func (s *DBService) bulkMailRecipientAllowed(ctx context.Context, recipient bulkMailRecipient) (bool, error) {
	if s.db == nil {
		return false, ErrUnavailable
	}
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var email string
	err := s.db.QueryRowContext(checkCtx, `SELECT email FROM v2_user WHERE id = $1`, recipient.ID).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("无法复核收件人，已停止群发: %w", err)
	}
	if strings.TrimSpace(email) != recipient.Email {
		return false, nil
	}
	exclusions, err := s.loadBulkMailExclusions(checkCtx)
	if err != nil {
		return false, err
	}
	return !exclusions.Matches(recipient.ID), nil
}
