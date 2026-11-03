package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	usersvc "forest/go-api/internal/user"
)

type investigationPartition struct {
	IDs     []int64 `json:"user_ids"`
	Kind    string  `json:"kind"`
	Host    string  `json:"host"`
	GroupID int64   `json:"group_id"`
	MergeID int64   `json:"merged_into,omitempty"`
}

func lockInvestigationAddresses(ctx context.Context, tx *sql.Tx) error {
	tables := []string{"v2_insider_rule", "v2_node_address_rule", "v2_node_address_group", "v2_node_address_binding"}
	for _, kind := range []string{"shadowsocks", "vmess", "trojan", "tuic", "hysteria", "vless", "anytls", "v2node"} {
		tables = append(tables, "v2_server_"+kind)
	}
	_, err := tx.ExecContext(ctx, "LOCK TABLE "+strings.Join(tables, ",")+" IN SHARE ROW EXCLUSIVE MODE")
	return err
}

func (s *DBService) healthyObservation(ctx context.Context, tx *sql.Tx, g InvestigationGroup, groups []InvestigationGroup) (*InvestigationGroup, error) {
	var port int64
	if err := tx.QueryRowContext(ctx, `SELECT check_port FROM v2_dispatch_monitor WHERE id=$1`, g.MonitorID).Scan(&port); err != nil {
		return nil, err
	}
	for _, v := range groups {
		if v.ID == g.ID || v.RootID != g.RootID || v.Kind != "observation" || v.ManualOnly || len(v.UserIDs) < 2 || v.ReadyAt == 0 {
			continue
		}
		var otherPort int64
		if err := tx.QueryRowContext(ctx, `SELECT check_port FROM v2_dispatch_monitor WHERE id=$1`, v.MonitorID).Scan(&otherPort); err != nil {
			return nil, err
		}
		if port != otherPort {
			continue
		}
		key, states, fresh, err := investigationProbeConfig(ctx, tx, v.MonitorID)
		if err != nil {
			return nil, err
		}
		if !fresh || key != v.ConfigKey {
			continue
		}
		healthy := true
		for _, p := range states {
			if !p.Success || s.dispatchProbeResetBlocked(p.ProbeID) {
				healthy = false
				break
			}
			samples, e := investigationSamples(ctx, tx, p.dispatchSplitCandidate, v.EpochAt)
			if e != nil {
				return nil, e
			}
			if len(samples) < 2 || !samples[0].Success || !samples[1].Success || !dispatchPoolStateFresh(sql.NullInt64{Int64: samples[1].ReportedAt, Valid: true}, samples[0].ReportedAt, p.Interval, p.Timeout) {
				healthy = false
				break
			}
		}
		if healthy {
			return &v, nil
		}
	}
	return nil, nil
}

func (s *DBService) applyInvestigation(ctx context.Context, tx *sql.Tx, g InvestigationGroup, groups []InvestigationGroup, evidence investigationEvidence, before []usersvc.DispatchEntry, duration int64, finish func(string) error) error {
	// Address changes, pool consumption and the two automatic systems serialize
	// on the same advisory lock. Existing address writers are also table-locked.
	if err := lockInvestigationAddresses(ctx, tx); err != nil {
		return err
	}
	actual, err := usersvc.DispatchEntriesFrom(ctx, tx)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(before, actual) {
		return finish("下发规则发生变化，等待重新确认")
	}
	settings, err := readInvestigationSettings(ctx, tx, false)
	if err != nil {
		return err
	}
	inScope, err := investigationGroupInScope(ctx, tx, settings.Scope, g.RootID)
	if err != nil {
		return err
	}
	if !inScope {
		return finish("不在当前生效范围，保留分组和地址，暂停自动处理")
	}
	pulled, recent := map[int64]bool{}, map[int64]bool{}
	rows, err := tx.QueryContext(ctx, `SELECT d.user_id,bool_or(d.delivered_at >= $4::bigint-7200) FROM (
SELECT group_id,generation,user_id,delivered_at FROM v2_dispatch_investigation_delivery WHERE group_id=$1 AND generation=$2
UNION ALL
SELECT group_id,generation,user_id,delivered_at FROM v2_dispatch_investigation_delivery_recent WHERE group_id=$1 AND generation=$2
) d JOIN v2_dispatch_investigation_member m ON m.group_id=d.group_id AND m.user_id=d.user_id WHERE d.delivered_at>=$3 AND d.delivered_at<$4 GROUP BY d.user_id`, g.ID, g.Generation, g.EpochAt, evidence.First)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var isRecent bool
		if err = rows.Scan(&id, &isRecent); err != nil {
			break
		}
		pulled[id] = true
		recent[id] = isRecent
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	all := investigationGroupIDs(g)
	yes, no := investigationPullPartition(all, pulled)
	recentIDs, olderIDs := investigationPullPartition(yes, recent)
	kind := "filtered"
	parts := []investigationPartition{}
	switch {
	case len(yes) == 0:
		kind = "no_pulls"
		parts = append(parts, investigationPartition{IDs: all, Kind: g.Kind})
	case len(no) == 0 && (len(recentIDs) == 0 || len(olderIDs) == 0):
		kind = "bisected"
		mid := (len(all) + 1) / 2
		groupKind := "candidate"
		if len(recentIDs) > 0 {
			groupKind = "recent"
		}
		parts = append(parts, investigationPartition{IDs: all[:mid], Kind: groupKind}, investigationPartition{IDs: all[mid:], Kind: groupKind})
	default:
		for _, p := range []investigationPartition{{IDs: recentIDs, Kind: "recent"}, {IDs: olderIDs, Kind: "candidate"}, {IDs: no, Kind: "observation"}} {
			if len(p.IDs) > 0 {
				parts = append(parts, p)
			}
		}
	}
	for i := range parts {
		p := &parts[i]
		if len(p.IDs) == 1 {
			p.Kind = "confirmed"
			p.Host = g.Host
			continue
		}
		if p.Kind == "observation" && kind == "filtered" {
			target, e := s.healthyObservation(ctx, tx, g, groups)
			if e != nil {
				return e
			}
			if target != nil {
				p.MergeID = target.ID
				p.Host = target.Host
				p.GroupID = target.ID
			}
		}
	}
	needed := 0
	for _, p := range parts {
		if p.Host == "" {
			needed++
		}
	}
	refs, err := dispatchPoolReferences(ctx, tx)
	if err != nil {
		return err
	}
	candidate := dispatchSplitCandidate{ID: g.MonitorID}
	pool := []DispatchPoolSave{}
	if needed > 0 {
		pool, err = s.dispatchSplitPoolLimit(ctx, tx, refs, candidate, false, nil, needed)
		if err != nil {
			return err
		}
		if len(pool) < needed {
			return finish(fmt.Sprintf("等待 %d 个同检测端口的健康未占用备用 IP", needed))
		}
		pool = pool[:needed]
	}
	// Create FK bindings before taking pool row locks (probe reports use that
	// same order). Savepoint makes a waiting state an all-or-nothing operation.
	if _, err = tx.ExecContext(ctx, `SAVEPOINT investigation_apply`); err != nil {
		return err
	}
	now := time.Now().Unix()
	moves := map[int64]string{}
	attempt := func() error {
		index := 0
		for i := range parts {
			p := &parts[i]
			monitor := g.MonitorID
			if p.Host == "" {
				p.Host = pool[index].IP
				index++
				var e error
				monitor, e = investigationCloneMonitor(ctx, tx, g.MonitorID, p.Host)
				if e != nil {
					return e
				}
			}
			if p.MergeID > 0 {
				if _, e := tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET generation=generation+1,epoch_at=$2,ready_at=0,revision=revision+1,reason='新成员加入，重新观察' WHERE id=$1`, p.MergeID, now); e != nil {
					return e
				}
			} else if kind == "no_pulls" {
				p.GroupID = g.ID
				name := g.Name
				if !strings.Contains(name, "无人拉取") {
					name += " · 无人拉取"
				}
				if _, e := tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET name=$2,host=$3,monitor_id=$4,generation=generation+1,epoch_at=$5,ready_at=0,config_key='',revision=revision+1,no_pull_count=no_pull_count+1,reason='本轮无人拉取，成员不变，已更换入口' WHERE id=$1`, g.ID, name, p.Host, monitor, now); e != nil {
					return e
				}
			} else {
				name := investigationGroupName(p.Kind)
				if e := tx.QueryRowContext(ctx, `INSERT INTO v2_dispatch_investigation_group(root_id,parent_id,legacy_root_id,name,kind,host,monitor_id,manual_only,epoch_at,created_at,reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10) RETURNING id`, g.RootID, g.ID, g.LegacyRootID, name, p.Kind, p.Host, monitor, len(p.IDs) == 1, now, map[bool]string{true: "自动产生单人组，仅人工操作", false: "等待新入口确认正常"}[len(p.IDs) == 1]).Scan(&p.GroupID); e != nil {
					return e
				}
			}
			raw, _ := json.Marshal(p.IDs)
			if _, e := tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_member SET group_id=$2 WHERE group_id=$1 AND user_id IN(SELECT value::bigint FROM jsonb_array_elements_text($3::jsonb))`, g.ID, p.GroupID, string(raw)); e != nil {
				return e
			}
			for _, id := range p.IDs {
				moves[id] = p.Host
			}
		}
		if needed > 0 {
			selected, e := s.dispatchSplitPoolLimit(ctx, tx, refs, candidate, true, pool, needed)
			if e != nil {
				return e
			}
			if len(selected) != needed {
				return fmt.Errorf("备用 IP 健康或占用状态发生变化")
			}
		}
		if kind != "no_pulls" {
			if _, e := tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET active=FALSE,revision=revision+1,reason='本轮已完成筛选' WHERE id=$1`, g.ID); e != nil {
				return e
			}
		}
		after, e := usersvc.DispatchEntriesFrom(ctx, tx)
		if e != nil {
			return e
		}
		if e = verifyInvestigationMove(before, after, g.Host, moves); e != nil {
			return e
		}
		if e = checkDispatchCapacity(ctx, tx); e != nil {
			return e
		}
		// Late results must not commit an action after the evidence changed.
		key, states, fresh, e := investigationProbeConfig(ctx, tx, g.MonitorID)
		if e != nil {
			return e
		}
		if !fresh || key != g.ConfigKey {
			return fmt.Errorf("监控配置或新鲜证据发生变化")
		}
		latestEvidence, reason, e := s.investigationEvidenceWithDuration(ctx, tx, g, states, before, duration)
		if e != nil {
			return e
		}
		if reason != "" {
			return fmt.Errorf("%s", reason)
		}
		if latestEvidence.First != evidence.First {
			return fmt.Errorf("故障起点发生变化，已取消本次处理")
		}
		if g.LegacyRootID > 0 {
			if _, e = tx.ExecContext(ctx, `INSERT INTO v2_dispatch_auto_split_cooldown(root_group_id,last_success_at) VALUES($1,$2) ON CONFLICT(root_group_id) DO UPDATE SET last_success_at=GREATEST(EXCLUDED.last_success_at,v2_dispatch_auto_split_cooldown.last_success_at)`, g.LegacyRootID, now); e != nil {
				return e
			}
		}
		return investigationAudit(ctx, tx, g.RootID, g.ID, kind, evidence.First, map[string]any{"before": g, "pulled_ids": yes, "recent_ids": recentIDs, "older_ids": olderIDs, "recent_window_minutes": 120, "unpulled_ids": no, "partitions": parts, "evidence": evidence, "reason": map[string]string{"filtered": "按首次失败前120分钟及本轮实际拉取记录筛选", "bisected": "全部拉取过且属于同一时间类别，按实际人数二分", "no_pulls": "无人拉取，成员不变"}[kind]})
	}
	if err = attempt(); err != nil {
		if _, e := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT investigation_apply`); e != nil {
			return e
		}
		return finish("本轮未修改：" + err.Error())
	}
	if _, err = tx.ExecContext(ctx, `RELEASE SAVEPOINT investigation_apply`); err != nil {
		return err
	}
	if err = tx.Commit(); err == nil {
		s.invalidateDispatchCatalog()
	}
	return err
}

// Project the expected ownership of every host, including unaffected IDs and
// unrelated nodes, rather than merely asserting the new group's own members.
func verifyInvestigationMove(before, after []usersvc.DispatchEntry, old string, moves map[int64]string) error {
	expected := map[string][]splitEditSpan{}
	for _, e := range before {
		expected[e.Host] = splitEntrySpans(e)
	}
	for id, host := range moves {
		if host == old {
			continue
		}
		left := []splitEditSpan{}
		for _, sp := range expected[old] {
			if id < sp.a || id > sp.b {
				left = append(left, sp)
				continue
			}
			if sp.a < id {
				left = append(left, splitEditSpan{sp.a, id - 1})
			}
			if id < sp.b {
				left = append(left, splitEditSpan{id + 1, sp.b})
			}
		}
		expected[old] = left
		expected[host] = append(expected[host], splitEditSpan{id, id})
	}
	canonical := func(m map[string][]splitEditSpan) map[string][]splitEditSpan {
		out := map[string][]splitEditSpan{}
		for host, spans := range m {
			sort.Slice(spans, func(i, j int) bool { return spans[i].a < spans[j].a })
			merged := []splitEditSpan{}
			for _, sp := range spans {
				if len(merged) > 0 && (sp.a <= merged[len(merged)-1].b || sp.a-1 == merged[len(merged)-1].b) {
					merged[len(merged)-1].b = max(merged[len(merged)-1].b, sp.b)
				} else {
					merged = append(merged, sp)
				}
			}
			if len(merged) > 0 {
				out[host] = merged
			}
		}
		return out
	}
	got := map[string][]splitEditSpan{}
	for _, e := range after {
		got[e.Host] = splitEntrySpans(e)
	}
	if !reflect.DeepEqual(canonical(expected), canonical(got)) {
		return fmt.Errorf("实际下发与预期分组不一致，已回滚全部改动")
	}
	return nil
}
