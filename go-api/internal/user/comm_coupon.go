package user

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

func (s *DBService) CommConfig(context.Context) (map[string]any, error) {
	cfg := s.currentConfig()
	withdrawMethods := cfg.CommissionWithdrawMethods
	if len(withdrawMethods) == 0 {
		withdrawMethods = []string{"支付宝", "USDT", "Paypal"}
	}

	return map[string]any{
		"is_telegram":                    boolToInt64(cfg.TelegramBotEnable),
		"telegram_discuss_link":          emptyStringToNil(cfg.TelegramDiscussLink),
		"stripe_pk":                      cfg.StripePKLive,
		"withdraw_methods":               withdrawMethods,
		"withdraw_close":                 boolToInt64(cfg.WithdrawCloseEnable),
		"currency":                       fallbackString(cfg.Currency, "CNY"),
		"currency_symbol":                fallbackString(cfg.CurrencySymbol, "¥"),
		"commission_distribution_enable": boolToInt64(cfg.CommissionDistEnabled),
		"commission_distribution_l1":     cfg.CommissionDistL1,
		"commission_distribution_l2":     cfg.CommissionDistL2,
		"commission_distribution_l3":     cfg.CommissionDistL3,
	}, nil
}

func (s *DBService) StripePublicKey(ctx context.Context, paymentID int64) (string, error) {
	if s.db == nil {
		return "", ErrUnavailable
	}
	if paymentID <= 0 {
		return "", ErrInvalidParameter
	}

	var rawConfig string
	err := s.db.QueryRowContext(ctx, `SELECT config
FROM v2_payment
WHERE id = $1 AND payment = 'StripeCredit'
LIMIT 1`, paymentID).Scan(&rawConfig)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", errors.New("payment is not found")
		}
		return "", fmt.Errorf("query stripe payment config: %w", err)
	}

	var payload map[string]any
	if strings.TrimSpace(rawConfig) != "" {
		if err := json.Unmarshal([]byte(rawConfig), &payload); err != nil {
			return "", fmt.Errorf("decode payment config: %w", err)
		}
	}
	return strings.TrimSpace(fmt.Sprint(payload["stripe_pk_live"])), nil
}

func (s *DBService) CheckCoupon(ctx context.Context, userID int64, code string, planID *int64) (map[string]any, error) {
	return s.checkCoupon(ctx, userID, strings.TrimSpace(code), planID, false)
}

func (s *DBService) CheckNewcomerCoupon(ctx context.Context, userID int64) (map[string]any, error) {
	return s.checkCoupon(ctx, userID, "", nil, true)
}

func (s *DBService) checkCoupon(ctx context.Context, userID int64, code string, planID *int64, newcomer bool) (map[string]any, error) {
	if s.db == nil {
		return nil, ErrUnavailable
	}

	if !newcomer && code == "" {
		return nil, errors.New("Coupon cannot be empty")
	}
	if newcomer && s.cfg.NewcomerCouponID <= 0 {
		return nil, ErrCouponInvalid
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin coupon check transaction: %w", err)
	}
	defer tx.Rollback()

	if newcomer {
		err := tx.QueryRowContext(ctx, `SELECT code FROM v2_coupon WHERE id = $1 FOR UPDATE`, s.cfg.NewcomerCouponID).Scan(&code)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrCouponInvalid
		}
		if err != nil {
			return nil, fmt.Errorf("query newcomer coupon: %w", err)
		}
	}
	coupon, ok, err := s.loadCouponTx(ctx, tx, code)
	if err != nil {
		return nil, err
	}
	if !ok || (newcomer && coupon.ID != s.cfg.NewcomerCouponID) {
		return nil, ErrCouponInvalid
	}

	now := time.Now().Unix()
	personalEndedAt, err := s.checkCouponWindow(ctx, tx, coupon, userID, now)
	if err != nil {
		return nil, err
	}

	if planID != nil && coupon.LimitPlanIDs.Valid && coupon.LimitPlanIDs.String != "" {
		if !containsInt64(parseIDString(coupon.LimitPlanIDs.String), *planID) {
			return nil, ErrCouponPlanRestricted
		}
	}

	if coupon.LimitUseWithUser.Valid {
		var usedCount int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM v2_order WHERE coupon_id = $1 AND user_id = $2 AND status NOT IN (0, 2)`, coupon.ID, userID).Scan(&usedCount); err != nil {
			return nil, fmt.Errorf("query coupon usage count: %w", err)
		}
		if usedCount >= coupon.LimitUseWithUser.Int64 {
			return nil, ErrCouponUserLimit
		}
	}

	result := map[string]any{
		"id":                  coupon.ID,
		"code":                code,
		"type":                coupon.Type,
		"value":               coupon.Value,
		"show":                coupon.Show,
		"limit_use":           nullInt64Any(coupon.LimitUse),
		"limit_use_with_user": nullInt64Any(coupon.LimitUseWithUser),
		"limit_plan_ids":      parseIDString(coupon.LimitPlanIDs.String),
		"limit_period":        parseStringList(coupon.LimitPeriod.String),
		"started_at":          coupon.StartedAt,
		"ended_at":            coupon.EndedAt,
	}
	if personalEndedAt > 0 {
		result["personal_ended_at"] = personalEndedAt
		result["server_now"] = now
	}
	return result, nil
}

const newcomerCouponSeconds int64 = 24 * 60 * 60

func (s *DBService) checkCouponWindow(ctx context.Context, tx *sql.Tx, coupon couponRecord, userID, now int64) (int64, error) {
	switch {
	case coupon.Show == 0:
		return 0, ErrCouponInvalid
	case coupon.LimitUse.Valid && coupon.LimitUse.Int64 <= 0:
		return 0, ErrCouponUnavailable
	case now < coupon.StartedAt:
		return 0, ErrCouponNotStarted
	case now > coupon.EndedAt:
		return 0, ErrCouponExpired
	}
	if id := s.cfg.NewcomerCouponID; id <= 0 || coupon.ID != id {
		return 0, nil
	}
	var registeredAt int64
	if err := tx.QueryRowContext(ctx, `SELECT created_at FROM v2_user WHERE id = $1`, userID).Scan(&registeredAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrCouponInvalid
		}
		return 0, fmt.Errorf("read registration date for newcomer coupon: %w", err)
	}
	if registeredAt <= 0 || registeredAt < coupon.StartedAt || registeredAt > now {
		return 0, ErrCouponInvalid
	}
	endsAt := min(registeredAt+newcomerCouponSeconds, coupon.EndedAt)
	if now >= endsAt {
		return 0, ErrCouponExpired
	}
	return endsAt, nil
}

func emptyStringToNil(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return value
}

func fallbackString(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
