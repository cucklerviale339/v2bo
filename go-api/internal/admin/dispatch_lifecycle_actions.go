package admin

import (
	"context"
	"encoding/json"
	"strconv"
	"time"
)

type InvestigationRelease struct {
	ID       int64    `json:"id"`
	Revision int64    `json:"revision"`
	UserIDs  []string `json:"user_ids"`
}

// Releasing global ownership restores the existing business selectors. It
// never creates new rules or changes unrelated users' node permissions.
func (s *DBService) ReleaseInvestigation(ctx context.Context, v InvestigationRelease) error {
	if v.ID < 1 || v.Revision < 1 || len(v.UserIDs) == 0 || len(v.UserIDs) > 20000 {
		return splitEditInvalid("请选择要退出全站管理的成员")
	}
	if err := s.ensureInvestigation(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = acquireInvestigationLock(ctx, tx, true); err != nil {
		return err
	}
	groups, err := readInvestigationGroupsWhere(ctx, tx, `g.active AND g.id=$1 AND g.route_scope='global'`, v.ID)
	if err != nil {
		return err
	}
	if len(groups) != 1 || groups[0].Revision != v.Revision {
		return splitEditInvalid("分组已变化，请刷新后重试")
	}
	g := groups[0]
	allowed := map[int64]bool{}
	for _, id := range investigationGroupIDs(g) {
		allowed[id] = true
	}
	ids := []int64{}
	seen := map[int64]bool{}
	for _, raw := range v.UserIDs {
		id, e := strconv.ParseInt(raw, 10, 64)
		if e != nil || !allowed[id] {
			return splitEditInvalid("成员不属于当前分组")
		}
		if !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	if err = lockInvestigationAddresses(ctx, tx); err != nil {
		return err
	}
	raw, _ := json.Marshal(ids)
	now := time.Now().Unix()
	if _, err = tx.ExecContext(ctx, `DELETE FROM v2_dispatch_global_member WHERE group_id=$1 AND user_id IN(SELECT value::bigint FROM jsonb_array_elements_text($2::jsonb))`, g.ID, string(raw)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET normal_since=0,normal_checkpoints='{}',epoch_at=$3,ready_at=0,generation=generation+1,revision=revision+1 WHERE id=$1 OR (route_scope='business' AND active AND id IN(SELECT group_id FROM v2_dispatch_investigation_member WHERE user_id IN(SELECT value::bigint FROM jsonb_array_elements_text($2::jsonb))))`, g.ID, string(raw), now); err != nil {
		return err
	}
	if err = investigationAudit(ctx, tx, g.RootID, g.ID, "global_released", 0, map[string]any{"user_ids": ids, "host": g.Host, "reason": "人工退出全站管理，恢复原业务规则及有效业务归属"}); err != nil {
		return err
	}
	if err = tx.Commit(); err == nil {
		s.invalidateDispatchCatalog()
	}
	return err
}
