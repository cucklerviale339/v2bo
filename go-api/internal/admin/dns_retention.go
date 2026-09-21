package admin

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const dnsFailoverRetentionDays int64 = 3
const dnsFailoverCleanupBatchSize int64 = 5000

type dnsFailoverRetentionExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func deleteDNSFailoverRetentionRows(ctx context.Context, execer dnsFailoverRetentionExecer, query string, cutoff, batchSize int64) error {
	if batchSize <= 0 {
		return fmt.Errorf("DNS cleanup batch size must be positive")
	}
	for {
		result, err := execer.ExecContext(ctx, query, cutoff, batchSize)
		if err != nil {
			return err
		}
		deleted, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if deleted < batchSize {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
}

func (s *DBService) cleanupDNSFailoverRetention(ctx context.Context) error {
	cleanupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := s.ensureDNSFailoverSchema(cleanupCtx); err != nil {
		return err
	}
	cutoff := time.Now().Unix() - dnsFailoverRetentionDays*86400
	for _, query := range []string{
		`WITH doomed AS (SELECT id FROM v2_dns_failover_log WHERE created_at < $1 ORDER BY id LIMIT $2)
DELETE FROM v2_dns_failover_log WHERE id IN (SELECT id FROM doomed)`,
		`WITH doomed AS (SELECT id FROM v2_dns_probe_result_inbox WHERE created_at < $1 ORDER BY id LIMIT $2)
DELETE FROM v2_dns_probe_result_inbox WHERE id IN (SELECT id FROM doomed)`,
		`WITH doomed AS (SELECT id FROM v2_dns_failover_event WHERE notified_at IS NOT NULL AND created_at < $1 ORDER BY id LIMIT $2)
DELETE FROM v2_dns_failover_event WHERE id IN (SELECT id FROM doomed)`,
	} {
		if err := deleteDNSFailoverRetentionRows(cleanupCtx, s.db, query, cutoff, dnsFailoverCleanupBatchSize); err != nil {
			return fmt.Errorf("cleanup DNS monitoring history: %w", err)
		}
	}
	return nil
}
