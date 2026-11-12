package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	usersvc "forest/go-api/internal/user"
	"reflect"
)

// Numeric business rules may admit new accounts; stable rosters must not.
// New accounts continue in the original receiving group while its endpoint
// remains unchanged; stage groups receive only individually qualified users.
// A lone new account never causes an automatic IP allocation.
func (s *DBService) admitInvestigationMembers(ctx context.Context, tx *sql.Tx, now int64, scope string) error {
	base, err := usersvc.DispatchEntriesBeforeInvestigationFrom(ctx, tx)
	if err != nil {
		return err
	}
	_, effective, err := usersvc.DispatchEntriesWithInvestigationMembersFrom(ctx, tx)
	if err != nil {
		return err
	}
	groups, err := readInvestigationGroupsWhere(ctx, tx, `g.route_scope='business'`)
	if err != nil {
		return err
	}
	byHost := map[string]usersvc.DispatchEntry{}
	for _, e := range base {
		byHost[e.Host] = e
	}
	for _, root := range groups {
		if root.ID != root.RootID || root.ManualOnly || root.Policy != "smart" {
			continue
		}
		inScope, e := investigationGroupInScope(ctx, tx, scope, root.ID)
		if e != nil {
			return e
		}
		if !inScope {
			continue
		}
		var origin string
		err = tx.QueryRowContext(ctx, `SELECT origin_host FROM v2_dispatch_investigation_member WHERE root_id=$1 ORDER BY user_id LIMIT 1`, root.ID).Scan(&origin)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return err
		}
		entry, ok := byHost[origin]
		if !ok {
			continue
		}
		var live bool
		if err = tx.QueryRowContext(ctx, `SELECT enabled AND NOT deleted FROM v2_dispatch_monitor WHERE id=$1`, root.MonitorID).Scan(&live); err != nil {
			return err
		}
		if !live {
			continue
		}
		all, e := usersvc.DispatchAccountIDs(ctx, tx, entry)
		if e != nil {
			return e
		}
		known := map[int64]bool{}
		rows, e := tx.QueryContext(ctx, `SELECT user_id FROM v2_dispatch_investigation_member WHERE origin_host=$1 UNION SELECT w.user_id FROM v2_dispatch_global_member w JOIN v2_dispatch_investigation_group g ON g.id=w.group_id AND g.active`, origin)
		if e != nil {
			return e
		}
		for rows.Next() {
			var id int64
			if e = rows.Scan(&id); e != nil {
				break
			}
			known[id] = true
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			return e
		}
		_, incoming := investigationPullPartition(all, known)
		if len(incoming) == 0 {
			continue
		}
		if err = lockInvestigationAddresses(ctx, tx); err != nil {
			return err
		}
		freshBase, e := usersvc.DispatchEntriesBeforeInvestigationFrom(ctx, tx)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(base, freshBase) {
			return nil
		}
		var target InvestigationGroup
		if root.Active && !root.RosterFrozen && root.Host == origin {
			target = root
		}
		if target.ID == 0 {
			active := currentInvestigationGroups(groups, effective)
			other, e := s.healthyObservation(ctx, tx, root, active)
			if e != nil {
				return e
			}
			if other != nil {
				target = *other
			}
		}
		if target.ID == 0 && len(incoming) < 2 {
			continue
		}
		if _, err = tx.ExecContext(ctx, `SAVEPOINT lifecycle_admission`); err != nil {
			return err
		}
		attempt := func() error {
			if target.ID == 0 {
				refs, e := dispatchPoolReferences(ctx, tx)
				if e != nil {
					return e
				}
				pool, e := s.lifecyclePool(ctx, tx, root, refs, 1)
				if e != nil {
					return e
				}
				if len(pool) == 0 {
					return sql.ErrNoRows
				}
				monitor, e := investigationCloneMonitor(ctx, tx, root.MonitorID, pool[0].IP)
				if e != nil {
					return e
				}
				if e = tx.QueryRowContext(ctx, `INSERT INTO v2_dispatch_investigation_group(root_id,parent_id,legacy_root_id,name,kind,host,monitor_id,epoch_at,created_at,reason) VALUES($1,$1,$2,'观察','observation',$3,$4,$5,$5,'新增用户独立观察') RETURNING id`, root.ID, root.LegacyRootID, pool[0].IP, monitor, now).Scan(&target.ID); e != nil {
					return e
				}
				target.Host = pool[0].IP
				selected, e := s.dispatchSplitPoolLimit(ctx, tx, refs, dispatchSplitCandidate{ID: root.MonitorID}, true, pool, 1)
				if e != nil {
					return e
				}
				if len(selected) != 1 {
					return sql.ErrNoRows
				}
			} else {
				if _, e := tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET epoch_at=$2,generation=generation+1,ready_at=0,revision=revision+1,reason='新成员加入，按个人记录观察' WHERE id=$1`, target.ID, now); e != nil {
					return e
				}
			}
			raw, _ := json.Marshal(incoming)
			if _, e := tx.ExecContext(ctx, `INSERT INTO v2_dispatch_investigation_member(root_id,origin_host,user_id,group_id) SELECT $1,$2,value::bigint,$3 FROM jsonb_array_elements_text($4::jsonb)`, root.ID, origin, target.ID, string(raw)); e != nil {
				return e
			}
			if e := checkDispatchCapacity(ctx, tx); e != nil {
				return e
			}
			return investigationAudit(ctx, tx, root.ID, target.ID, "members_admitted", 0, map[string]any{"user_ids": incoming, "host": target.Host, "reason": "按具体用户接收新增成员，稳定组不接收新人"})
		}
		if err = attempt(); err != nil {
			if _, e = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT lifecycle_admission`); e != nil {
				return e
			}
			if err != sql.ErrNoRows {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, `RELEASE SAVEPOINT lifecycle_admission`); err != nil {
			return err
		}
	}
	return nil
}
