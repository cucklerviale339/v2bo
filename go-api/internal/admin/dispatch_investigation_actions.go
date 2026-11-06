package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	usersvc "forest/go-api/internal/user"
)

type InvestigationAction struct {
	ID       int64 `json:"id"`
	Revision int64 `json:"revision"`
}

var ErrInvestigationBusy = errors.New("其他入口任务正在处理，请稍后重试")

// Poll a nonblocking advisory lock so a short database lock timeout does not
// abort the transaction. The request deadline bounds both waiting and work.
func acquireInvestigationLock(ctx context.Context, tx *sql.Tx, immediate bool) error {
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		var locked bool
		if err := tx.QueryRowContext(waitCtx, `SELECT pg_try_advisory_xact_lock(7642309023)`).Scan(&locked); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if waitCtx.Err() != nil {
				return ErrInvestigationBusy
			}
			return err
		}
		if locked {
			return nil
		}
		if !immediate {
			return ErrInvestigationBusy
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return ErrInvestigationBusy
		case <-timer.C:
		}
	}
}

// Config identity includes the probe roster and enable flags. A run change
// alone is resumable only through edges written atomically at service startup.
func investigationRestartMatches(ctx context.Context, tx *sql.Tx, g InvestigationGroup, key string) (bool, error) {
	old, next := strings.Split(g.ConfigKey, ":"), strings.Split(key, ":")
	if len(old) < 7 || len(old) != len(next) || strings.Join(old[:6], ":") != strings.Join(next[:6], ":") {
		return false, nil
	}
	var version int64
	if _, err := fmt.Sscan(next[0], &version); err != nil {
		return false, nil
	}
	for i := 6; i < len(old); i++ {
		var oldID, oldRun, oldActive, id, run, active int64
		if n, _ := fmt.Sscanf(old[i], "%d/%d/%d", &oldID, &oldRun, &oldActive); n != 3 {
			return false, nil
		}
		if n, _ := fmt.Sscanf(next[i], "%d/%d/%d", &id, &run, &active); n != 3 || id != oldID || active != oldActive || run < oldRun {
			return false, nil
		}
		if run == oldRun {
			continue
		}
		var linked bool
		if err := tx.QueryRowContext(ctx, `WITH RECURSIVE runs(run_id) AS (SELECT $4::bigint UNION SELECT r.from_run FROM v2_dispatch_monitor_restart r JOIN runs ON r.to_run=runs.run_id WHERE r.monitor_id=$1 AND r.probe_id=$2 AND r.version=$3) SELECT EXISTS(SELECT 1 FROM runs WHERE run_id=$5)`, g.MonitorID, id, version, run, oldRun).Scan(&linked); err != nil {
			return false, err
		}
		if !linked {
			return false, nil
		}
	}
	return true, nil
}

// Confirmation starts a new receipt generation rather than inventing a
// successful probe sample or retroactively selecting users from an unknown T.
func (s *DBService) ConfirmInvestigation(ctx context.Context, v InvestigationAction) error {
	if v.ID < 1 || v.Revision < 1 {
		return splitEditInvalid("分组或版本无效")
	}
	if err := s.ensureInvestigation(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout='1s'; SET LOCAL statement_timeout='5s'; SELECT pg_advisory_xact_lock(7642309023)`); err != nil {
		return err
	}
	settings, err := readInvestigationSettings(ctx, tx, true)
	if err != nil {
		return err
	}
	if !settings.Enabled {
		return splitEditInvalid("总开关已关闭")
	}
	if err = lockInvestigationAddresses(ctx, tx); err != nil {
		return err
	}
	groups, err := readInvestigationGroups(ctx, tx, true)
	if err != nil {
		return err
	}
	_, members, err := usersvc.DispatchEntriesWithInvestigationMembersFrom(ctx, tx)
	if err != nil {
		return err
	}
	groups = currentInvestigationGroups(groups, members)
	var g InvestigationGroup
	for _, x := range groups {
		if x.ID == v.ID {
			g = x
		}
	}
	if g.ID == 0 || g.Revision != v.Revision {
		return splitEditInvalid("分组已变化，请刷新后重试")
	}
	if g.ManualOnly || len(g.UserIDs) <= 1 {
		return splitEditInvalid("此分组仅允许人工编辑")
	}
	inScope, err := investigationGroupInScope(ctx, tx, settings.Scope, g.RootID)
	if err != nil {
		return err
	}
	if !inScope {
		return splitEditInvalid("分组不在当前生效范围")
	}
	key, probes, fresh, err := investigationProbeConfig(ctx, tx, g.MonitorID)
	if err != nil {
		return err
	}
	if !fresh {
		return splitEditInvalid("监控未启用、探针离线或数据过期")
	}
	for _, p := range probes {
		if s.dispatchProbeResetBlocked(p.ProbeID) {
			return splitEditInvalid("探针会话重置中")
		}
	}
	// Evidence timestamps are seconds. Exclude the entire click second to
	// prevent an earlier result/receipt in that second entering the new round.
	at := time.Now().Unix() + 1
	if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET config_key=$2,epoch_at=$3,ready_at=$3,generation=generation+1,revision=revision+1,reason='人工确认入口，重新观察' WHERE id=$1`, g.ID, key, at); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO v2_dispatch_investigation_confirmation(group_id,generation,confirmed_at) VALUES($1,$2,$3) ON CONFLICT(group_id) DO UPDATE SET generation=EXCLUDED.generation,confirmed_at=EXCLUDED.confirmed_at`, g.ID, g.Generation+1, at); err != nil {
		return err
	}
	if err = investigationAudit(ctx, tx, g.RootID, g.ID, "confirmed_entry", 0, map[string]any{"before": g, "host": g.Host, "confirmed_at": at, "generation": g.Generation + 1}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *DBService) TriggerInvestigation(ctx context.Context, v InvestigationAction) error {
	if v.ID < 1 || v.Revision < 1 {
		return splitEditInvalid("分组或版本无效")
	}
	// The automatic worker yields before taking its next group while a human
	// is waiting or executing. PostgreSQL remains the cross-process guard.
	s.dispatchAutoSplitMu.Lock()
	s.investigationManualPending++
	s.dispatchAutoSplitMu.Unlock()
	defer func() {
		s.dispatchAutoSplitMu.Lock()
		s.investigationManualPending--
		s.dispatchAutoSplitMu.Unlock()
	}()
	if err := s.ensureInvestigation(ctx); err != nil {
		return err
	}
	return s.processInvestigationAction(ctx, v.ID, v.Revision, true)
}
