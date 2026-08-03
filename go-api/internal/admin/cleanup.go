package admin

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

const cleanupLastCheckKey = "MAINTENANCE_CLEANUP_LAST_AT_"
const ticketAutoCloseAfter = 72 * time.Hour

func (s *DBService) CleanupRetention(ctx context.Context) error {
	if s.db == nil {
		return ErrUnavailable
	}

	now := time.Now()
	nowUnix := now.Unix()
	if err := s.autoCloseRepliedTickets(ctx, now); err != nil {
		return err
	}

	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Unix()

	lastRun, err := s.getInt64KV(ctx, cleanupLastCheckKey)
	if err != nil {
		return fmt.Errorf("query cleanup last runtime: %w", err)
	}
	if lastRun != nil && *lastRun >= todayStart {
		return nil
	}

	cfg := s.currentConfig()

	if cfg.MailLogKeepDays > 0 {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM v2_mail_log WHERE created_at < $1`, nowUnix-(cfg.MailLogKeepDays*86400)); err != nil {
			return fmt.Errorf("cleanup mail log: %w", err)
		}
	}
	if cfg.LogKeepDays > 0 {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM v2_log WHERE created_at < $1`, nowUnix-(cfg.LogKeepDays*86400)); err != nil {
			return fmt.Errorf("cleanup system log: %w", err)
		}
	}
	if cfg.StatUserKeepDays > 0 {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM v2_stat_user WHERE record_at < $1`, todayStart-(cfg.StatUserKeepDays*86400)); err != nil {
			return fmt.Errorf("cleanup user traffic stat: %w", err)
		}
	}
	if cfg.StatServerKeepDays > 0 {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM v2_stat_server WHERE record_at < $1`, todayStart-(cfg.StatServerKeepDays*86400)); err != nil {
			return fmt.Errorf("cleanup server traffic stat: %w", err)
		}
	}

	if _, err := s.db.ExecContext(ctx, `DELETE FROM v2_auth_session WHERE expire_at > 0 AND expire_at <= $1`, nowUnix); err != nil {
		return fmt.Errorf("cleanup expired auth session: %w", err)
	}
	if cfg.AuthSessionKeepDays > 0 {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM v2_auth_session WHERE updated_at < $1`, nowUnix-(cfg.AuthSessionKeepDays*86400)); err != nil {
			return fmt.Errorf("cleanup auth session history: %w", err)
		}
	}

	if _, err := s.db.ExecContext(ctx, `DELETE FROM v2_runtime_kv WHERE expire_at > 0 AND expire_at <= $1`, nowUnix); err != nil {
		return fmt.Errorf("cleanup expired runtime kv: %w", err)
	}
	if cfg.RuntimeKVKeepDays > 0 {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM v2_runtime_kv WHERE expire_at = 0 AND updated_at < $1`, nowUnix-(cfg.RuntimeKVKeepDays*86400)); err != nil {
			return fmt.Errorf("cleanup runtime kv history: %w", err)
		}
	}

	if cfg.FailedJobsKeepDays > 0 {
		cutoff := now.Add(-time.Duration(cfg.FailedJobsKeepDays) * 24 * time.Hour)
		if _, err := s.db.ExecContext(ctx, `DELETE FROM failed_jobs WHERE failed_at < $1`, cutoff); err != nil {
			return fmt.Errorf("cleanup failed jobs: %w", err)
		}
	}

	if _, err := s.db.ExecContext(ctx, `INSERT INTO v2_runtime_kv (k, v, expire_at, created_at, updated_at)
VALUES ($1, $2, 0, $3, $3)
ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v, expire_at = EXCLUDED.expire_at, updated_at = EXCLUDED.updated_at`,
		cleanupLastCheckKey, strconv.FormatInt(todayStart, 10), nowUnix,
	); err != nil {
		return fmt.Errorf("save cleanup last runtime: %w", err)
	}

	return nil
}

func (s *DBService) autoCloseRepliedTickets(ctx context.Context, now time.Time) error {
	nowUnix := now.Unix()
	cutoff := now.Add(-ticketAutoCloseAfter).Unix()
	if _, err := s.db.ExecContext(ctx, `UPDATE v2_ticket
SET status = 1, updated_at = $1
WHERE status = 0 AND reply_status = 1 AND updated_at <= $2`, nowUnix, cutoff); err != nil {
		return fmt.Errorf("auto-close replied tickets: %w", err)
	}
	return nil
}
