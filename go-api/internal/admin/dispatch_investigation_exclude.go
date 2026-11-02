package admin

import (
	"context"
	"database/sql"
)

// Exclude deleted monitors from this module. Retaining inactive records avoids
// rewriting dispatch rules, historical evidence, membership and family limits.
// Catalog overrides and automation already require an active group.
func excludeDeletedInvestigations(ctx context.Context, tx *sql.Tx) (bool, error) {
	result, err := tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group g SET active=FALSE,revision=g.revision+1,generation=g.generation+1 FROM v2_dispatch_monitor m WHERE m.id=g.monitor_id AND m.deleted AND g.active`)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count > 0, err
}

// Old deletions are excluded on startup, including when automation is off.
func (s *DBService) excludeDeletedInvestigations(ctx context.Context) error {
	var pending bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v2_dispatch_investigation_group g JOIN v2_dispatch_monitor m ON m.id=g.monitor_id WHERE m.deleted AND g.active)`).Scan(&pending); err != nil || !pending {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout='1s'; SET LOCAL statement_timeout='5s'`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(7642309023)`); err != nil {
		return err
	}
	changed, err := excludeDeletedInvestigations(ctx, tx)
	if err != nil {
		return err
	}
	if err = tx.Commit(); err == nil && changed {
		s.invalidateDispatchCatalog()
	}
	return err
}
