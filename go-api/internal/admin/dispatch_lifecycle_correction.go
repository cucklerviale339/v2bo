package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	usersvc "forest/go-api/internal/user"
)

// Only undo system admissions. A later explicit member addition is an
// administrator's assignment and remains intact, even with unresolved risk.
func investigationStageCorrectionIDs(ctx context.Context, tx *sql.Tx, g InvestigationGroup) ([]int64, error) {
	// Expand each admission event once. Re-reading a large JSON audit for
	// every member becomes expensive on stages with thousands of users.
	rows, err := tx.QueryContext(ctx, `WITH admissions AS MATERIALIZED (
SELECT value::bigint AS user_id,max(e.id) FILTER(WHERE e.kind<>'edited') AS automatic,max(e.id) FILTER(WHERE e.kind='edited') AS manual
FROM v2_dispatch_investigation_event e
CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(NULLIF(CASE WHEN e.kind='edited' THEN e.payload->'added_ids' ELSE e.payload->'user_ids' END,'null'::jsonb),'[]')) u(value)
WHERE ((e.kind IN('stable_promoted','whitelist_promoted') AND e.payload->>'target_group_id'=$1::bigint::text) OR (e.kind='edited' AND e.group_id=$1::bigint)) AND value ~ '^[1-9][0-9]*$'
GROUP BY value::bigint)
SELECT DISTINCT m.user_id FROM v2_dispatch_investigation_member m JOIN v2_user u ON u.id=m.user_id JOIN admissions a ON a.user_id=m.user_id
WHERE m.group_id=$1 AND (`+investigationRiskBlocked+` OR (
`+investigationRiskReleasedAt+`>0 AND EXISTS(SELECT 1 FROM v2_dispatch_investigation_event admission
WHERE admission.id=a.automatic AND admission.created_at<`+investigationRiskReleasedAt+`+$2::bigint)))
AND COALESCE(a.automatic,0)>COALESCE(a.manual,0)
ORDER BY m.user_id`, g.ID, func() int64 {
		if g.LifecycleRole == "whitelist" {
			return whitelistObserveSeconds
		}
		return stableObserveSeconds
	}())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	wanted := map[int64]bool{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		wanted[id] = true
	}
	ids, _ := investigationPullPartition(investigationGroupIDs(g), wanted)
	return ids, rows.Err()
}

// Run under the ordinary investigation lock, before a stage can promote or
// fail over. Preserve unaffected people's generations, receipt clocks and
// addresses. Never release these users to an old, possibly failed fallback.
func (s *DBService) correctInvestigationStage(ctx context.Context, tx *sql.Tx, g InvestigationGroup, before []usersvc.DispatchEntry, finish func(string) error) (bool, error) {
	if g.RouteScope != "business" || (g.LifecycleRole != "stable" && g.LifecycleRole != "whitelist") || g.Policy != "smart" || g.ManualOnly {
		return false, nil
	}
	ids, err := investigationStageCorrectionIDs(ctx, tx, g)
	if err != nil || len(ids) == 0 {
		return false, err
	}
	if err := lockInvestigationAddresses(ctx, tx); err != nil {
		return true, err
	}
	actual, members, err := usersvc.DispatchEntriesWithInvestigationMembersFrom(ctx, tx)
	if err != nil {
		return true, err
	}
	current := currentInvestigationGroups([]InvestigationGroup{g}, members)
	if !reflect.DeepEqual(before, actual) || len(current) != 1 || !reflect.DeepEqual(current[0].UserIDs, g.UserIDs) {
		return true, finish("阶段纠正前下发关系发生变化，等待重新核对")
	}
	move, err := planInvestigationBusinessMove(ctx, tx, g.ID, ids)
	if err != nil {
		return true, err
	}
	refs, err := dispatchPoolReferences(ctx, tx)
	if err != nil {
		return true, err
	}
	pool, err := s.lifecycleStagePool(ctx, tx, refs, false, nil)
	if err != nil {
		return true, err
	}
	if len(pool) != 1 {
		return true, finish(fmt.Sprintf("待纠正 %d 名历史晋级成员：等待健康未占用备用 IP", len(ids)))
	}
	if _, err := tx.ExecContext(ctx, `SAVEPOINT lifecycle_correct`); err != nil {
		return true, err
	}
	attempt := func() error {
		host := pool[0].IP
		monitor, err := cloneDispatchPoolMonitorAtPort(ctx, tx, g.MonitorID, host, pool[0].Port)
		if err != nil {
			return err
		}
		var target int64
		now := time.Now().Unix()
		if err := tx.QueryRowContext(ctx, `INSERT INTO v2_dispatch_investigation_group(root_id,parent_id,legacy_root_id,name,kind,host,monitor_id,epoch_at,created_at,reason,route_scope,lifecycle_role,policy,roster_frozen)
VALUES($1,$2,$3,'待复核','observation',$4,$5,$6,$6,'历史晋级成员独立复核，确认故障并完成细分前禁止晋级','business','ordinary','smart',TRUE) RETURNING id`, g.RootID, g.ID, g.LegacyRootID, host, monitor, now).Scan(&target); err != nil {
			return err
		}
		raw, _ := json.Marshal(ids)
		if _, err := tx.ExecContext(ctx, `DELETE FROM v2_dispatch_stability_receipt d USING v2_dispatch_investigation_member m WHERE m.group_id=$1 AND m.user_id IN(SELECT value::bigint FROM jsonb_array_elements_text($2::jsonb)) AND d.origin_host=m.origin_host AND d.user_id=m.user_id`, g.ID, string(raw)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_member SET group_id=$2 WHERE group_id=$1 AND user_id IN(SELECT value::bigint FROM jsonb_array_elements_text($3::jsonb))`, g.ID, target, string(raw)); err != nil {
			return err
		}
		// Retained (including currently overridden) members must not silently
		// lose their stage if their business assignment becomes effective again.
		if _, err := tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET revision=revision+1,active=EXISTS(SELECT 1 FROM v2_dispatch_investigation_member WHERE group_id=$1),reason='已将历史错误晋级成员移回观察，其余成员进度保留' WHERE id=$1`, g.ID); err != nil {
			return err
		}
		locked, err := s.lifecycleStagePool(ctx, tx, refs, true, pool)
		if err != nil {
			return err
		}
		if len(locked) != 1 {
			return fmt.Errorf("纠正入口健康或占用状态已变化")
		}
		after, err := usersvc.DispatchEntriesFrom(ctx, tx)
		if err != nil {
			return err
		}
		if err := move.verify(ctx, tx, before, after, InvestigationGroup{ID: target, Host: host, Generation: 1}); err != nil {
			return err
		}
		if err := checkDispatchCapacity(ctx, tx); err != nil {
			return err
		}
		return investigationAudit(ctx, tx, g.RootID, g.ID, "stage_corrected", 0, map[string]any{"before": g, "user_ids": ids, "target_group_id": target, "host": host, "promotion_hold": true, "reason": "自动晋级成员独立分组，确认故障并完成细分前禁止晋级；明确手工加入者与其余成员保持原下发及进度"})
	}
	if err := attempt(); err != nil {
		if _, rollback := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT lifecycle_correct`); rollback != nil {
			return true, rollback
		}
		return true, finish("阶段纠正待重试：" + err.Error())
	}
	if _, err := tx.ExecContext(ctx, `RELEASE SAVEPOINT lifecycle_correct`); err != nil {
		return true, err
	}
	if err := tx.Commit(); err != nil {
		return true, err
	}
	s.invalidateDispatchCatalog()
	return true, nil
}
