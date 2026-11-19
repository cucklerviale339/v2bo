package admin

import (
	"context"
	"time"
)

const investigationTimeoutReason = "自动处理超时，等待重试"

func (s *DBService) recordInvestigationTimeout(ctx context.Context, g InvestigationGroup) error {
	statusCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(statusCtx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(statusCtx, `SET LOCAL lock_timeout='250ms'; SET LOCAL statement_timeout='750ms'`); err != nil {
		return err
	}
	var locked bool
	if err = tx.QueryRowContext(statusCtx, `SELECT pg_try_advisory_xact_lock(7642309023)`).Scan(&locked); err != nil || !locked {
		return err
	}
	// A manual edit, another completed action or a newer observation must win.
	// Change only the status, preserving receipts, timing, routes and revisions.
	if _, err = tx.ExecContext(statusCtx, `UPDATE v2_dispatch_investigation_group SET reason=$2
WHERE id=$1 AND active AND NOT manual_only AND policy<>'fixed'
AND revision=$3 AND generation=$4 AND epoch_at=$5 AND host=$6 AND reason=$7
AND monitor_id=$8 AND config_key=$9`, g.ID, investigationTimeoutReason, g.Revision, g.Generation, g.EpochAt, g.Host, g.Reason, g.MonitorID, g.ConfigKey); err != nil {
		return err
	}
	return tx.Commit()
}
