package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	usersvc "forest/go-api/internal/user"
)

type investigationProbe struct {
	dispatchSplitCandidate
	ResolvedIP string
}
type investigationEvidence struct {
	First    int64              `json:"first_failure_at"`
	Probes   []int64            `json:"probe_ids"`
	Controls map[int64][]string `json:"controls"`
}

func investigationSamples(ctx context.Context, q dispatchQueryer, c dispatchSplitCandidate, from int64) ([]DispatchHistorySample, error) {
	rows, err := q.QueryContext(ctx, `SELECT payload FROM v2_dispatch_history WHERE source='entry' AND kind='sample' AND target_id=$1 AND probe_id=$2 AND version=$3 AND run_id=$4 AND created_at>=$5 ORDER BY sequence DESC LIMIT 15000`, c.ID, c.ProbeID, c.Version, c.RunID, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DispatchHistorySample{}
	for rows.Next() {
		var raw []byte
		var v DispatchHistorySample
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Returns a cutoff only when its beginning is preceded by a fresh successful
// sample. Unknown starts, broken sample continuity and other error types fail shut.
func investigationTimeoutStart(samples []DispatchHistorySample, c dispatchSplitCandidate, now, epoch int64) (int64, bool) {
	if c.Success || c.Error != "timeout" || !dispatchSplitFresh(c, now) || len(samples) < 2 {
		return 0, false
	}
	if samples[0].Sequence != c.Sequence || samples[0].ReportedAt != c.Reported {
		return 0, false
	}
	previous := c.Reported
	first := int64(0)
	for i, x := range samples {
		if x.Version != c.Version || x.RunID != c.RunID || (i > 0 && !dispatchEvidenceFollows(samples[i-1], x, c)) || x.ReportedAt < epoch || x.ReportedAt > previous || !dispatchPoolStateFresh(sql.NullInt64{Int64: x.ReportedAt, Valid: true}, previous, c.Interval, c.Timeout) {
			return 0, false
		}
		if x.Success {
			return first, first > 0 && now-first >= 600
		}
		if x.Error != "timeout" {
			return 0, false
		}
		first = x.ReportedAt
		previous = x.ReportedAt
	}
	return 0, false
}

func investigationControlSpan(samples []DispatchHistorySample, c dispatchSplitCandidate, first, now int64) bool {
	if !c.Success || !dispatchSplitFresh(c, now) || len(samples) < 2 || samples[0].Sequence != c.Sequence || samples[0].ReportedAt != c.Reported {
		return false
	}
	previous := c.Reported
	for i, x := range samples {
		if !x.Success || x.Version != c.Version || x.RunID != c.RunID || (i > 0 && !dispatchEvidenceFollows(samples[i-1], x, c)) || x.ReportedAt > previous || !dispatchPoolStateFresh(sql.NullInt64{Int64: x.ReportedAt, Valid: true}, previous, c.Interval, c.Timeout) {
			return false
		}
		if x.ReportedAt <= first-max(int64(60), c.Interval) {
			return true
		}
		previous = x.ReportedAt
	}
	return false
}

func investigationProbeConfig(ctx context.Context, tx *sql.Tx, monitor int64) (string, []investigationProbe, bool, error) {
	var version, port, interval, timeout int64
	var host string
	var enabled, deleted bool
	if err := tx.QueryRowContext(ctx, `SELECT host,version,check_port,enabled,deleted,check_interval_sec,tcp_timeout_ms FROM v2_dispatch_monitor WHERE id=$1`, monitor).Scan(&host, &version, &port, &enabled, &deleted, &interval, &timeout); err != nil {
		return "", nil, false, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT b.probe_id,b.run_id,p.enabled,COALESCE(p.last_heartbeat_at,0),COALESCE(st.version,0),COALESCE(st.sequence,0),COALESCE(st.reported_at,0),COALESCE(st.success,FALSE),COALESCE(st.error,''),COALESCE(st.resolved_ip,'') FROM v2_dispatch_monitor_probe b JOIN v2_dns_probe p ON p.id=b.probe_id LEFT JOIN v2_dispatch_monitor_state st ON st.monitor_id=b.monitor_id AND st.probe_id=b.probe_id WHERE b.monitor_id=$1 ORDER BY b.probe_id`, monitor)
	if err != nil {
		return "", nil, false, err
	}
	defer rows.Close()
	key := fmt.Sprintf("%d:%d:%d:%d:%t:%t", version, port, interval, timeout, enabled, deleted)
	ready := enabled && !deleted
	out := []investigationProbe{}
	now := time.Now().Unix()
	for rows.Next() {
		var x investigationProbe
		var active, stVersion, hb int64
		x.ID = monitor
		x.Host = host
		x.Version = version
		x.Interval = interval
		x.Timeout = timeout
		if err = rows.Scan(&x.ProbeID, &x.RunID, &active, &hb, &stVersion, &x.Sequence, &x.Reported, &x.Success, &x.Error, &x.ResolvedIP); err != nil {
			return "", nil, false, err
		}
		key += fmt.Sprintf(":%d/%d/%d", x.ProbeID, x.RunID, active)
		ready = ready && active == 1 && hb >= now-defaultProbeOfflineSec && stVersion == version && dispatchSplitFresh(x.dispatchSplitCandidate, now)
		out = append(out, x)
	}
	return key, out, ready && len(out) > 0, rows.Err()
}

func (s *DBService) investigationEvidence(ctx context.Context, tx *sql.Tx, g InvestigationGroup, probes []investigationProbe, entries []usersvc.DispatchEntry) (investigationEvidence, string, error) {
	now := time.Now().Unix()
	result := investigationEvidence{Controls: map[int64][]string{}}
	targetIPs := map[int64]string{}
	var failedAt int64
	if err := tx.QueryRowContext(ctx, `SELECT delivery_failure_at FROM v2_dispatch_investigation_health WHERE id=1`).Scan(&failedAt); err != nil {
		return result, "", err
	}
	failedAt = max(failedAt, usersvc.InvestigationDeliveryFailureAt())
	s.dispatchHistoryMu.Lock()
	historyFailure := s.dispatchHistoryLastFailureAt
	s.dispatchHistoryMu.Unlock()
	if failedAt >= g.EpochAt || historyFailure >= g.EpochAt {
		return result, "证据写入曾失败，请恢复正常后重新观察", nil
	}
	for _, p := range probes {
		if s.dispatchProbeResetBlocked(p.ProbeID) {
			return result, "探针会话重置中", nil
		}
		samples, err := investigationSamples(ctx, tx, p.dispatchSplitCandidate, g.EpochAt)
		if err != nil {
			return result, "", err
		}
		first, ok := investigationTimeoutStart(samples, p.dispatchSplitCandidate, now, g.EpochAt)
		if !ok {
			return result, "等待连续超时满 10 分钟，或探针结果不一致", nil
		}
		targetIPs[p.ProbeID] = usersvc.NormalizeDispatchHost(p.ResolvedIP)
		for _, sample := range samples {
			if sample.Success {
				if sample.ResolvedIP != "" {
					targetIPs[p.ProbeID] = usersvc.NormalizeDispatchHost(sample.ResolvedIP)
				}
				break
			}
		}
		if result.First == 0 || first < result.First {
			result.First = first
		}
		result.Probes = append(result.Probes, p.ProbeID)
	}
	// Select controls by identities that were healthy at T and throughout the
	// entire incident. Several failing peers do not invalidate healthy controls.
	actual := map[string]bool{}
	for _, e := range entries {
		actual[e.Host] = true
	}
	states, err := dispatchSplitStates(ctx, tx)
	if err != nil {
		return result, "", err
	}
	for _, p := range probes {
		available := map[string]bool{}
		healthy := map[string]string{}
		configuredOthers := 0
		bound, e := tx.QueryContext(ctx, `SELECT m.host FROM v2_dispatch_monitor m JOIN v2_dispatch_monitor_probe b ON b.monitor_id=m.id WHERE b.probe_id=$1 AND m.id<>$2 AND m.enabled AND NOT m.deleted`, p.ProbeID, g.MonitorID)
		if e != nil {
			return result, "", e
		}
		for bound.Next() {
			var host string
			if e = bound.Scan(&host); e != nil {
				break
			}
			if actual[host] {
				configuredOthers++
			}
		}
		if e == nil {
			e = bound.Err()
		}
		bound.Close()
		if e != nil {
			return result, "", e
		}
		for _, c := range states {
			if c.ID == g.MonitorID || c.ProbeID != p.ProbeID || !actual[c.Host] || s.dispatchProbeResetBlocked(c.ProbeID) {
				continue
			}
			var resolved string
			if err = tx.QueryRowContext(ctx, `SELECT resolved_ip FROM v2_dispatch_monitor_state WHERE monitor_id=$1 AND probe_id=$2`, c.ID, c.ProbeID).Scan(&resolved); err != nil {
				return result, "", err
			}
			identity := resolved
			if identity == "" {
				identity = c.Host
			}
			identity = usersvc.NormalizeDispatchHost(identity)
			if identity == targetIPs[p.ProbeID] || identity == usersvc.NormalizeDispatchHost(g.Host) || c.Host == g.Host {
				continue
			}
			available[identity] = true
			if !c.Success || !dispatchSplitFresh(c, now) {
				continue
			}
			samples, e := investigationSamples(ctx, tx, c, max(g.EpochAt, result.First-max(defaultProbeOfflineSec, 2*(c.Interval+(c.Timeout+999)/1000))))
			if e != nil {
				return result, "", e
			}
			if investigationControlSpan(samples, c, result.First, now) {
				healthy[identity] = c.Host
			}
		}
		needed := 2
		if len(available) == 1 && configuredOthers == 1 {
			needed = 1
		}
		if len(healthy) < needed {
			return result, "缺少贯穿故障期间的独立正常对照入口，等待确认", nil
		}
		hosts := []string{}
		for _, host := range healthy {
			hosts = append(hosts, host)
		}
		sort.Strings(hosts)
		result.Controls[p.ProbeID] = hosts
	}
	return result, "", nil
}

func investigationGroupIDs(g InvestigationGroup) []int64 {
	out := []int64{}
	for _, raw := range g.UserIDs {
		var id int64
		fmt.Sscan(raw, &id)
		if id > 0 {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
func investigationPullPartition(all []int64, pulled map[int64]bool) ([]int64, []int64) {
	yes, no := []int64{}, []int64{}
	for _, id := range all {
		if pulled[id] {
			yes = append(yes, id)
		} else {
			no = append(no, id)
		}
	}
	return yes, no
}

func (s *DBService) processInvestigation(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout='500ms'; SET LOCAL statement_timeout='5s'`); err != nil {
		return err
	}
	var locked bool
	if err = tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(7642309023)`).Scan(&locked); err != nil || !locked {
		return err
	}
	settings, err := readInvestigationSettings(ctx, tx, true)
	if err != nil || !settings.Enabled {
		return err
	}
	groups, err := readInvestigationGroups(ctx, tx, true)
	if err != nil {
		return err
	}
	var g InvestigationGroup
	for _, v := range groups {
		if v.ID == id {
			g = v
		}
	}
	if g.ID == 0 || g.ManualOnly || len(g.UserIDs) <= 1 {
		return nil
	}
	now := time.Now().Unix()
	finish := func(reason string) error {
		if _, e := tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET reason=$2 WHERE id=$1`, id, reason); e != nil {
			return e
		}
		return tx.Commit()
	}
	inScope, err := investigationGroupInScope(ctx, tx, settings.Scope, g.RootID)
	if err != nil {
		return err
	}
	if !inScope {
		return finish("不在当前生效范围，保留分组和地址，暂停自动处理")
	}
	key, probes, fresh, err := investigationProbeConfig(ctx, tx, g.MonitorID)
	if err != nil {
		return err
	}
	if g.ConfigKey == "" {
		// The first worker pass must not erase pulls already made since this
		// newly assigned address began dispatching.
		if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET config_key=$2 WHERE id=$1`, id, key); err != nil {
			return err
		}
		g.ConfigKey = key
	}
	if g.ConfigKey != key {
		if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET config_key=$2,epoch_at=$3,generation=generation+1,ready_at=0,revision=revision+1,reason='监控配置或会话变更，重新观察' WHERE id=$1`, id, key, now); err != nil {
			return err
		}
		return tx.Commit()
	}
	if !fresh {
		if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET ready_at=0,epoch_at=$2,generation=generation+1 WHERE id=$1 AND ready_at<>0`, id, now); err != nil {
			return err
		}
		return finish("监控未启用、探针离线或数据过期")
	}
	entries, err := usersvc.DispatchEntriesFrom(ctx, tx)
	if err != nil {
		return err
	}
	actual := map[string]usersvc.DispatchEntry{}
	for _, e := range entries {
		actual[e.Host] = e
	}
	for _, userID := range investigationGroupIDs(g) {
		if !usersvc.DispatchEntryContains(actual[g.Host], userID) {
			return finish("实际下发关系已变化，暂停自动处理")
		}
	}
	allSuccess := true
	for _, p := range probes {
		allSuccess = allSuccess && p.Success
	}
	if allSuccess {
		var failedAt int64
		if err = tx.QueryRowContext(ctx, `SELECT delivery_failure_at FROM v2_dispatch_investigation_health WHERE id=1`).Scan(&failedAt); err != nil {
			return err
		}
		failedAt = max(failedAt, usersvc.InvestigationDeliveryFailureAt())
		s.dispatchHistoryMu.Lock()
		failedAt = max(failedAt, s.dispatchHistoryLastFailureAt)
		s.dispatchHistoryMu.Unlock()
		if failedAt >= g.EpochAt {
			if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET ready_at=0,epoch_at=$2,generation=generation+1,revision=revision+1 WHERE id=$1`, id, now+1); err != nil {
				return err
			}
			return finish("证据恢复后重新开始观察")
		}
		if g.ReadyAt == 0 {
			if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET ready_at=$2 WHERE id=$1`, id, now); err != nil {
				return err
			}
		}
		return finish("正常观察中")
	}
	if g.ReadyAt == 0 {
		return finish("新入口尚未确认正常，不按本轮失败筛选")
	}
	evidence, reason, err := s.investigationEvidence(ctx, tx, g, probes, entries)
	if err != nil {
		return err
	}
	if reason != "" {
		return finish(reason)
	}
	if evidence.First < max(g.ReadyAt, settings.ArmedAt) {
		return finish("故障起点早于有效观察期")
	}
	// Share limits across the whole immutable family and the previous splitter.
	var last, count int64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(max(created_at),0) FROM v2_dispatch_investigation_event WHERE root_id=$1 AND kind IN('filtered','bisected','no_pulls')`, g.RootID).Scan(&last); err != nil {
		return err
	}
	if g.LegacyRootID > 0 {
		var legacy int64
		if err = tx.QueryRowContext(ctx, `SELECT GREATEST(COALESCE((SELECT last_success_at FROM v2_dispatch_auto_split_cooldown WHERE root_group_id=$1),0),COALESCE((SELECT max(updated_at) FROM v2_dispatch_auto_split_operation WHERE root_group_id=$1 AND status='succeeded'),0))`, g.LegacyRootID).Scan(&legacy); err != nil {
			return err
		}
		last = max(last, legacy)
	}
	if last > 0 && now-last < settings.EntryWindowMinutes*60 {
		return finish("同一原始组及其后代处于频率限制窗口")
	}
	if err = tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM v2_dispatch_investigation_event WHERE kind IN('filtered','bisected','no_pulls') AND created_at>$1)+(SELECT count(*) FROM v2_dispatch_auto_split_operation WHERE status='succeeded' AND updated_at>$1)`, now-settings.GlobalWindowMinutes*60).Scan(&count); err != nil {
		return err
	}
	if count >= settings.GlobalMax {
		return finish("达到全局自动处理频率限制")
	}
	return s.applyInvestigation(ctx, tx, g, groups, evidence, entries, finish)
}
