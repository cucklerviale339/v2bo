package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"forest/go-api/internal/platform/addrutil"
	"forest/go-api/internal/platform/userselector"
	usersvc "forest/go-api/internal/user"
)

type DispatchAutoSplitGroup struct {
	ID            int64  `json:"id"`
	RootGroupID   int64  `json:"root_group_id"`
	ParentGroupID int64  `json:"parent_group_id"`
	MonitorID     int64  `json:"monitor_id"`
	Host          string `json:"host"`
	IDRange       string `json:"id_range"`
	Revision      int64  `json:"revision"`
	Active        bool   `json:"active"`
	HasChildren   bool   `json:"has_children"`
}
type DispatchSplitGroupEdit struct {
	ID            int64  `json:"id"`
	Revision      int64  `json:"revision"`
	ParentGroupID int64  `json:"parent_group_id"`
	Host          string `json:"host"`
	IDRange       string `json:"id_range"`
}
type DispatchSplitEditRequest struct {
	Groups []DispatchSplitGroupEdit `json:"groups"`
}

func readDispatchSplitGroups(ctx context.Context, q usersvc.DispatchQueryer) ([]DispatchAutoSplitGroup, error) {
	rows, err := q.QueryContext(ctx, `SELECT g.id,COALESCE(g.root_group_id,g.id),COALESCE(g.parent_group_id,0),g.monitor_id,g.host,g.id_range,g.revision,m.enabled AND NOT m.deleted,EXISTS(SELECT 1 FROM v2_dispatch_auto_split_group c WHERE c.parent_group_id=g.id) FROM v2_dispatch_auto_split_group g JOIN v2_dispatch_monitor m ON m.id=g.monitor_id ORDER BY g.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DispatchAutoSplitGroup{}
	for rows.Next() {
		var g DispatchAutoSplitGroup
		if err = rows.Scan(&g.ID, &g.RootGroupID, &g.ParentGroupID, &g.MonitorID, &g.Host, &g.IDRange, &g.Revision, &g.Active, &g.HasChildren); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
func splitEditInvalid(message string) error {
	return fmt.Errorf("%w: %s", ErrDNSProbeInvalidRequest, message)
}

// Historical operation snapshots are immutable. Group revisions protect edits
// from concurrent splitting, reparenting and stale administrator forms.
func (s *DBService) EditDispatchSplitGroups(ctx context.Context, req DispatchSplitEditRequest) error {
	if len(req.Groups) < 1 || len(req.Groups) > 100 {
		return splitEditInvalid("请选择 1 至 100 个分组")
	}
	seen := map[int64]bool{}
	for i := range req.Groups {
		v := &req.Groups[i]
		v.Host = normalizeDispatchMonitorHost(v.Host)
		if v.ID <= 0 || v.Revision <= 0 || v.ParentGroupID < 0 || seen[v.ID] || !addrutil.IsIPOrHostname(v.Host) {
			return splitEditInvalid("分组编号、版本或下发地址无效")
		}
		seen[v.ID] = true
	}
	if err := s.ensureDispatchAutoSplitSchema(ctx); err != nil {
		return err
	}
	if err := s.ensureDispatchMonitorSchema(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout='1500ms'; SET LOCAL statement_timeout='5s'`); err != nil {
		return err
	}
	if _, err = readDispatchAutoSplitSettings(ctx, tx, true); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(7642309023)`); err != nil {
		return err
	}
	tables := []string{"v2_insider_rule", "v2_node_address_rule", "v2_node_address_group", "v2_node_address_binding"}
	for _, kind := range []string{"shadowsocks", "vmess", "trojan", "tuic", "hysteria", "vless", "anytls", "v2node"} {
		tables = append(tables, "v2_server_"+kind)
	}
	if _, err = tx.ExecContext(ctx, "LOCK TABLE "+strings.Join(tables, ",")+" IN SHARE ROW EXCLUSIVE MODE"); err != nil {
		return err
	}
	groups, err := readDispatchSplitGroups(ctx, tx)
	if err != nil {
		return err
	}
	original := map[int64]DispatchAutoSplitGroup{}
	next := map[int64]DispatchAutoSplitGroup{}
	for _, g := range groups {
		original[g.ID] = g
		next[g.ID] = g
	}
	liveEdits := []DispatchSplitGroupEdit{}
	for _, v := range req.Groups {
		g, ok := next[v.ID]
		if !ok || g.Revision != v.Revision {
			return splitEditInvalid("分组已变化，请刷新后重新编辑")
		}
		if v.ParentGroupID != 0 {
			if _, ok := next[v.ParentGroupID]; !ok {
				return splitEditInvalid("父分组不存在")
			}
		}
		if v.Host != g.Host || v.IDRange != g.IDRange {
			if !g.Active {
				return splitEditInvalid("已二分或已停止监控的分组只能修改父子关系；请编辑当前子分组的范围和地址")
			}
			a, b, ok := userselector.ParseRange(strings.TrimSpace(v.IDRange))
			if !ok {
				return splitEditInvalid("ID 范围须为正整数起止范围，例如 100-199")
			}
			v.IDRange = dispatchSplitSpan(a, b)
			liveEdits = append(liveEdits, v)
		}
		g.ParentGroupID = v.ParentGroupID
		g.Host = v.Host
		g.IDRange = v.IDRange
		next[g.ID] = g
	}
	// Derive every root from the complete proposed graph, never trust client roots.
	for id, g := range next {
		path := map[int64]bool{}
		cur := id
		for {
			if path[cur] {
				return splitEditInvalid("父子分组不能形成循环")
			}
			path[cur] = true
			item, ok := next[cur]
			if !ok {
				return splitEditInvalid("分组关系不完整")
			}
			if item.ParentGroupID == 0 {
				g.RootGroupID = cur
				break
			}
			cur = item.ParentGroupID
		}
		next[id] = g
	}
	before, err := usersvc.DispatchEntriesFrom(ctx, tx)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	if err = editDispatchSplitRules(ctx, tx, before, original, liveEdits, now); err != nil {
		return err
	}
	// Carry the stricter old/new cooldown forward. Detaching or moving a subtree
	// must never reset the quota, and historical successes stay unchanged.
	stamps := map[int64]int64{}
	rows, err := tx.QueryContext(ctx, `SELECT root_group_id,max(at) FROM (SELECT root_group_id,updated_at AS at FROM v2_dispatch_auto_split_operation WHERE status='succeeded' UNION ALL SELECT root_group_id,last_success_at FROM v2_dispatch_auto_split_cooldown) q GROUP BY root_group_id`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var root, at int64
		if err = rows.Scan(&root, &at); err != nil {
			rows.Close()
			return err
		}
		stamps[root] = at
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	// Use a fixed point for batch moves through several roots in one request.
	for i := 0; i < len(groups); i++ {
		changed := false
		for id, g := range next {
			old := original[id]
			if stamps[old.RootGroupID] > stamps[g.RootGroupID] {
				stamps[g.RootGroupID] = stamps[old.RootGroupID]
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	ids := make([]int64, 0, len(next))
	for id := range next {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		g, old := next[id], original[id]
		if g.ParentGroupID == old.ParentGroupID && g.RootGroupID == old.RootGroupID && g.Host == old.Host && g.IDRange == old.IDRange {
			continue
		}
		if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_auto_split_group SET parent_group_id=NULLIF($2,0),root_group_id=$3,host=$4,id_range=$5,revision=revision+1 WHERE id=$1`, id, g.ParentGroupID, g.RootGroupID, g.Host, g.IDRange); err != nil {
			return err
		}
		if g.RootGroupID != old.RootGroupID || g.ParentGroupID != old.ParentGroupID {
			if _, err = tx.ExecContext(ctx, `INSERT INTO v2_dispatch_auto_split_cooldown(root_group_id,last_success_at) VALUES($1,$2) ON CONFLICT(root_group_id) DO UPDATE SET last_success_at=GREATEST(v2_dispatch_auto_split_cooldown.last_success_at,EXCLUDED.last_success_at)`, g.RootGroupID, stamps[g.RootGroupID]); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_auto_split_operation SET status='cancelled',reason='分组已由管理员编辑，取消旧观察',updated_at=$2 WHERE monitor_id=$1 AND status='waiting'`, g.MonitorID, now); err != nil {
			return err
		}
	}
	for _, v := range liveEdits {
		g := original[v.ID]
		var conflict bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v2_dispatch_monitor WHERE host=$1 AND id<>$2)`, v.Host, g.MonitorID).Scan(&conflict); err != nil {
			return err
		}
		if conflict {
			return splitEditInvalid("下发地址已有其他监控配置（含已删除入口），请选择独立地址")
		}
		if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_monitor SET host=$2,version=version+1 WHERE id=$1`, g.MonitorID, v.Host); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_monitor_probe SET run_id=run_id+1 WHERE monitor_id=$1`, g.MonitorID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM v2_dispatch_monitor_state WHERE monitor_id=$1`, g.MonitorID); err != nil {
			return err
		}
	}
	afterGroups, err := readDispatchSplitGroups(ctx, tx)
	if err != nil {
		return err
	}
	oldJSON, _ := json.Marshal(groups)
	newJSON, _ := json.Marshal(afterGroups)
	if _, err = tx.ExecContext(ctx, `INSERT INTO v2_dispatch_auto_split_edit(before_data,after_data,created_at) VALUES($1,$2,$3)`, string(oldJSON), string(newJSON), now); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.dispatchCacheMu.Lock()
	s.dispatchCachedHosts = nil
	s.dispatchCachedScopes = nil
	s.dispatchCacheAt = time.Time{}
	s.dispatchCacheMu.Unlock()
	return nil
}

type splitEditSpan struct{ a, b int64 }

func splitEntrySpans(e usersvc.DispatchEntry) []splitEditSpan {
	out := []splitEditSpan{}
	for _, raw := range e.UserIDRanges {
		a, b, ok := userselector.ParseRange(raw)
		if ok {
			out = append(out, splitEditSpan{a, b})
		}
	}
	for _, raw := range e.UserIDs {
		a, err := strconv.ParseInt(raw, 10, 64)
		if err == nil && a > 0 {
			out = append(out, splitEditSpan{a, a})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].a < out[j].a })
	return out
}
func splitScopesOutside(entries []usersvc.DispatchEntry, masks []splitEditSpan) map[string][]splitEditSpan {
	result := map[string][]splitEditSpan{}
	for _, e := range entries {
		spans := splitEntrySpans(e)
		for _, m := range masks {
			left := []splitEditSpan{}
			for _, s := range spans {
				if m.b < s.a || m.a > s.b {
					left = append(left, s)
					continue
				}
				if s.a < m.a {
					left = append(left, splitEditSpan{s.a, m.a - 1})
				}
				if s.b > m.b {
					left = append(left, splitEditSpan{m.b + 1, s.b})
				}
			}
			spans = left
		}
		if len(spans) > 0 {
			result[e.Host] = spans
		}
	}
	return result
}
func editDispatchSplitRules(ctx context.Context, tx *sql.Tx, before []usersvc.DispatchEntry, groups map[int64]DispatchAutoSplitGroup, edits []DispatchSplitGroupEdit, now int64) error {
	if len(edits) == 0 {
		return nil
	}
	byHost := map[string]usersvc.DispatchEntry{}
	for _, e := range before {
		byHost[e.Host] = e
	}
	masks := []splitEditSpan{}
	hosts := map[string]bool{}
	sources := map[string]bool{}
	for _, v := range edits {
		g := groups[v.ID]
		e, ok := byHost[g.Host]
		if !ok {
			return splitEditInvalid("原入口已不参与实际下发，请刷新配置")
		}
		oldA, oldB, ok := userselector.ParseRange(g.IDRange)
		if !ok || !reflect.DeepEqual(splitEntrySpans(e), []splitEditSpan{{oldA, oldB}}) {
			return splitEditInvalid("实际下发范围已被其他规则修改，请先核对节点地址规则")
		}
		a, b, _ := userselector.ParseRange(v.IDRange)
		masks = append(masks, splitEditSpan{oldA, oldB}, splitEditSpan{a, b})
		if hosts[v.Host] {
			return splitEditInvalid("各分组必须使用不同的下发地址")
		}
		hosts[v.Host] = true
		if v.Host != g.Host {
			if _, exists := byHost[v.Host]; exists {
				return splitEditInvalid("新地址已被其他实际下发入口占用")
			}
		}
		if len(e.Sources) == 0 {
			return splitEditInvalid("缺少可编辑的地址规则")
		}
		rawRange, _ := json.Marshal([]string{v.IDRange})
		for _, source := range e.Sources {
			table, prefix := "v2_node_address_rule", "节点地址规则 #"
			if strings.HasPrefix(source, "内鬼管理规则 #") {
				table, prefix = "v2_insider_rule", "内鬼管理规则 #"
			}
			if !strings.HasPrefix(source, prefix) {
				return splitEditInvalid("仅支持编辑二分生成的单范围地址规则")
			}
			if sources[source] {
				return splitEditInvalid("多个分组引用同一来源规则")
			}
			sources[source] = true
			id, err := strconv.ParseInt(strings.TrimPrefix(source, prefix), 10, 64)
			if err != nil {
				return splitEditInvalid("规则编号无效")
			}
			var host, ids, ranges, extras string
			if err = tx.QueryRowContext(ctx, `SELECT host,match_user_ids,match_user_id_ranges,extra_nodes FROM `+table+` WHERE id=$1 AND enabled=1`, id).Scan(&host, &ids, &ranges, &extras); err != nil {
				return err
			}
			var ri, rr, re []string
			if json.Unmarshal([]byte(ids), &ri) != nil || json.Unmarshal([]byte(ranges), &rr) != nil || json.Unmarshal([]byte(extras), &re) != nil || len(ri) != 0 || len(rr) != 1 || len(re) != 0 || normalizeDispatchMonitorHost(host) != g.Host || strings.ContainsAny(host, ",()") {
				return splitEditInvalid("来源规则含复杂地址、具体 ID 或额外节点，无法直接修改")
			}
			lo, hi, valid := userselector.ParseRange(rr[0])
			if !valid || lo != oldA || hi != oldB {
				return splitEditInvalid("来源范围与分组记录不一致")
			}
			if _, err = tx.ExecContext(ctx, `UPDATE `+table+` SET host=$2,match_user_id_ranges=$3,updated_at=$4 WHERE id=$1`, id, v.Host, string(rawRange), now); err != nil {
				return err
			}
		}
	}
	after, err := usersvc.DispatchEntriesFrom(ctx, tx)
	if err != nil {
		return err
	}
	actual := map[string]usersvc.DispatchEntry{}
	for _, e := range after {
		actual[e.Host] = e
	}
	for _, v := range edits {
		a, b, _ := userselector.ParseRange(v.IDRange)
		if !reflect.DeepEqual(splitEntrySpans(actual[v.Host]), []splitEditSpan{{a, b}}) {
			return splitEditInvalid("新范围与其他规则冲突，实际下发结果无法完整匹配；已取消全部修改")
		}
	}
	if !reflect.DeepEqual(splitScopesOutside(before, masks), splitScopesOutside(after, masks)) {
		return splitEditInvalid("修改影响了所选范围之外的下发配置，已取消全部修改")
	}
	return nil
}
