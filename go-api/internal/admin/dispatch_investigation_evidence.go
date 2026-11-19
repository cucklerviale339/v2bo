package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
	First              int64              `json:"first_failure_at"`
	Probes             []int64            `json:"probe_ids"`
	Controls           map[int64][]string `json:"controls"`
	Mode               string             `json:"mode"`
	CutoffSource       string             `json:"cutoff_source"`
	WindowFrom         int64              `json:"verification_from,omitempty"`
	Warnings           []string           `json:"warnings,omitempty"`
	ReceiptsIncomplete bool               `json:"receipts_incomplete,omitempty"`
}

func investigationSamples(ctx context.Context, q dispatchQueryer, c dispatchSplitCandidate, from int64) ([]DispatchHistorySample, error) {
	return investigationSamplesLimit(ctx, q, c, from, 15000)
}

func investigationSamplesLimit(ctx context.Context, q dispatchQueryer, c dispatchSplitCandidate, from int64, limit int) ([]DispatchHistorySample, error) {
	rows, err := q.QueryContext(ctx, `WITH RECURSIVE runs(run_id) AS (SELECT $4::bigint UNION SELECT r.from_run FROM v2_dispatch_monitor_restart r JOIN runs ON r.to_run=runs.run_id WHERE r.monitor_id=$1 AND r.probe_id=$2 AND r.version=$3) SELECT payload FROM v2_dispatch_history WHERE source='entry' AND kind='sample' AND target_id=$1 AND probe_id=$2 AND version=$3 AND run_id IN(SELECT run_id FROM runs) AND created_at>=$5 ORDER BY created_at DESC,id DESC LIMIT $6`, c.ID, c.ProbeID, c.Version, c.RunID, from, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DispatchHistorySample{}
	runs := []int64{}
	for rows.Next() {
		var raw []byte
		var v DispatchHistorySample
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		// Membership in the recursive run chain is checked in SQL. Normalize
		// that identity only; time and sequence continuity remain mandatory.
		runs = append(runs, v.RunID)
		v.RunID = c.RunID
		out = append(out, v)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	for i := 0; i+1 < len(out); i++ {
		if runs[i] == runs[i+1] {
			continue
		}
		// Proven startup edges establish provenance, never elapsed failure time.
		// Legacy PostgreSQL epoch casts round fractional seconds, while Go
		// receipts truncate them. Allow only that one-second precision difference.
		edges, e := q.QueryContext(ctx, `WITH RECURSIVE chain(run_id) AS (SELECT $4::bigint UNION SELECT r.from_run FROM v2_dispatch_monitor_restart r JOIN chain c ON r.to_run=c.run_id WHERE r.monitor_id=$1 AND r.probe_id=$2 AND r.version=$3 AND r.created_at BETWEEN $6-1 AND $7+1) SELECT EXISTS(SELECT 1 FROM chain WHERE run_id=$5)`, c.ID, c.ProbeID, c.Version, runs[i], runs[i+1], out[i+1].ReportedAt, out[i].ReportedAt)
		if e != nil {
			return nil, e
		}
		if edges.Next() {
			err = edges.Scan(&out[i].RecordedRestartBefore)
		} else {
			err = edges.Err()
		}
		edges.Close()
		if err != nil {
			return nil, err
		}
		out[i].UnverifiedRestartBefore = !out[i].RecordedRestartBefore
	}
	return out, nil
}

// Compatibility helpers for checking a complete, unbroken observation sequence.
func investigationTimeoutStart(samples []DispatchHistorySample, c dispatchSplitCandidate, now, epoch int64) (int64, bool) {
	return investigationTimeoutStartAfterConfirmation(samples, c, now, epoch, 0, 600)
}

func investigationTimeoutStartAfterConfirmation(samples []DispatchHistorySample, c dispatchSplitCandidate, now, epoch, confirmed, duration int64) (int64, bool) {
	first, reason := investigationTimeoutEvidence(samples, c, now, epoch, confirmed, duration)
	return first, reason == ""
}

func investigationTimeoutEvidence(samples []DispatchHistorySample, c dispatchSplitCandidate, now, epoch, confirmed, duration int64) (int64, string) {
	incident := investigationIncidentFrom(samples, c, epoch, confirmed, investigationIncident{})
	return investigationAutomaticDecision(incident, samples, c, now, duration)
}

func investigationAutomaticDecision(incident investigationIncident, samples []DispatchHistorySample, c dispatchSplitCandidate, now, duration int64) (int64, string) {
	if c.Success || !dispatchSplitFresh(c, now) {
		return 0, "等待全部探针新鲜且一致检测失败"
	}
	if incident.First == 0 || !incident.Baseline {
		return 0, "故障起点不明，保留本轮观察数据，可人工立即触发"
	}
	if incident.Uncertain {
		return 0, "故障期间存在未知检测空档，可人工立即触发"
	}
	if !investigationFailureWindow(samples, c, now, duration) {
		return 0, "等待当前连续检测失败满 10 分钟，原观察数据保留"
	}
	return incident.First, ""
}

func investigationControlSpan(samples []DispatchHistorySample, c dispatchSplitCandidate, first, now int64) bool {
	if !c.Success || !dispatchSplitFresh(c, now) || len(samples) < 2 || samples[0].Sequence != c.Sequence || samples[0].ReportedAt != c.Reported {
		return false
	}
	previous := c.Reported
	for i, x := range samples {
		if !x.Success || x.Version != c.Version || x.RunID != c.RunID || (i > 0 && (samples[i-1].RecordedRestartBefore || samples[i-1].UnverifiedRestartBefore || !investigationEvidenceFollows(samples[i-1], x, c))) || x.ReportedAt > previous {
			return false
		}
		if x.ReportedAt <= first-max(int64(60), c.Interval) {
			if c.Sequence >= 100000000000000000 && c.Sequence-x.Sequence < (c.Reported-first+max(int64(60), c.Interval))*int64(time.Second) {
				continue
			}
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
	return s.investigationEvidenceWithDuration(ctx, tx, g, probes, entries, 600)
}

func (s *DBService) investigationEvidenceWithDuration(ctx context.Context, tx *sql.Tx, g InvestigationGroup, probes []investigationProbe, entries []usersvc.DispatchEntry, duration int64) (investigationEvidence, string, error) {
	now := time.Now().Unix()
	result := investigationEvidence{Controls: map[int64][]string{}, Mode: "automatic", CutoffSource: "established_incident"}
	targetIPs := map[int64]string{}
	var failedAt int64
	if err := tx.QueryRowContext(ctx, `SELECT delivery_failure_at FROM v2_dispatch_investigation_health WHERE id=1`).Scan(&failedAt); err != nil {
		return result, "", err
	}
	failedAt = max(failedAt, usersvc.InvestigationDeliveryFailureAt())
	s.dispatchHistoryMu.Lock()
	historyFailure := s.dispatchHistoryLastFailureAt
	s.dispatchHistoryMu.Unlock()
	if historyFailure >= g.EpochAt {
		return result, "证据写入曾失败，请恢复正常后重新观察", nil
	}
	if failedAt >= g.EpochAt {
		result.ReceiptsIncomplete = true
		result.Warnings = append(result.Warnings, "拉取证据写入曾失败，本次只允许整组故障转移，不按缺失记录筛人")
	}
	for _, p := range probes {
		if s.dispatchProbeResetBlocked(p.ProbeID) {
			return result, "探针会话重置中", nil
		}
		samples, err := investigationSamples(ctx, tx, p.dispatchSplitCandidate, g.EpochAt)
		if err != nil {
			return result, "", err
		}
		incident, e := loadInvestigationIncident(ctx, tx, g, p, samples)
		if e != nil {
			return result, "", e
		}
		first, reason := investigationAutomaticDecision(incident, samples, p.dispatchSplitCandidate, now, duration)
		if reason != "" {
			return result, reason, nil
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
		window := p.Reported - duration
		if result.WindowFrom == 0 || window < result.WindowFrom {
			result.WindowFrom = window
		}
	}
	// Controls cover the same current verification window as the failing target.
	// Earlier upgrade downtime does not permanently poison healthy controls.
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
			samples, e := investigationSamples(ctx, tx, c, result.WindowFrom-max(defaultProbeOfflineSec, 2*(c.Interval+(c.Timeout+999)/1000)))
			if e != nil {
				return result, "", e
			}
			if investigationControlSpan(samples, c, result.WindowFrom, now) {
				healthy[identity] = c.Host
			}
		}
		needed := 2
		if len(available) == 1 && configuredOthers == 1 {
			needed = 1
		}
		if len(healthy) < needed {
			return result, "缺少贯穿当前故障确认窗口的独立正常对照入口", nil
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
	err := s.processInvestigationAction(ctx, id, 0, false)
	if errors.Is(err, ErrInvestigationBusy) {
		return nil
	}
	return err
}

func (s *DBService) processInvestigationAction(ctx context.Context, id, revision int64, immediate bool) (err error) {
	stage, host := "获取处理锁", ""
	defer func() {
		if err != nil && !errors.Is(err, ErrInvestigationBusy) && !errors.Is(err, ErrDNSProbeInvalidRequest) {
			err = fmt.Errorf("入口分组 #%d (%s)，阶段 %s: %w", id, host, stage, err)
		}
	}()
	if !immediate {
		s.dispatchAutoSplitMu.Lock()
		pending := s.investigationManualPending > 0
		s.dispatchAutoSplitMu.Unlock()
		if pending {
			return ErrInvestigationBusy
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	var failureGroup InvestigationGroup
	defer func() {
		// The action's transaction and context are unusable after a deadline.
		// Record retry status only after rollback, guarded by the saved round.
		_ = tx.Rollback()
		if !immediate && failureGroup.ID > 0 && errors.Is(err, context.DeadlineExceeded) {
			if statusErr := s.recordInvestigationTimeout(ctx, failureGroup); statusErr != nil {
				err = errors.Join(err, fmt.Errorf("记录超时重试状态: %w", statusErr))
			}
		}
	}()
	if _, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout='500ms'; SET LOCAL statement_timeout='5s'`); err != nil {
		return err
	}
	if err = acquireInvestigationLock(ctx, tx, immediate); err != nil {
		return err
	}
	stage = "读取设置与当前分组"
	settings, err := readInvestigationSettings(ctx, tx, true)
	if err != nil || !settings.Enabled {
		if err == nil && immediate {
			return splitEditInvalid("总开关已关闭")
		}
		return err
	}
	groups, err := readInvestigationGroupsWhere(ctx, tx, `g.active AND g.id=$1`, id)
	if err != nil {
		return err
	}
	stage = "核对实际下发关系"
	entries, members, err := usersvc.DispatchEntriesWithInvestigationMembersFrom(ctx, tx)
	if err != nil {
		return err
	}
	groups = currentInvestigationGroups(groups, members)
	var g InvestigationGroup
	for _, v := range groups {
		if v.ID == id {
			g = v
		}
	}
	if g.ID == 0 || g.ManualOnly || g.Policy == "fixed" || investigationSingleManual(g) {
		if immediate {
			return splitEditInvalid("分组不存在或仅允许人工编辑")
		}
		return nil
	}
	if immediate && g.Revision != revision {
		return splitEditInvalid("分组已变化，请刷新后重试")
	}
	failureGroup = g
	host = g.Host
	stage = "核对监控配置"
	now := time.Now().Unix()
	finish := func(reason string) error {
		if immediate {
			return splitEditInvalid(reason)
		}
		if _, e := tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET reason=$2 WHERE id=$1`, id, reason); e != nil {
			return e
		}
		return tx.Commit()
	}
	inScope, err := investigationGroupInScope(ctx, tx, settings.Scope, g.RootID)
	if g.RouteScope == "global" {
		inScope = true
	}
	if err != nil {
		return err
	}
	if !inScope {
		return finish("不在当前生效范围，保留分组和地址，暂停自动处理")
	}
	correctionPending := ""
	if !immediate && settings.LifecycleEnabled {
		stage = "纠正历史阶段晋级"
		// Waiting for a correction IP must not skip monitor reconciliation,
		// healthy observation or fault handling. A completed correction commits
		// its own transaction; a deferred correction leaves it open here.
		handled, e := s.correctInvestigationStage(ctx, tx, g, entries, func(reason string) error {
			correctionPending = reason
			return nil
		})
		if e != nil || (handled && correctionPending == "") {
			return e
		}
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
		if immediate {
			// Human execution preserves receipt ownership even if monitoring changed.
			if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET config_key=$2 WHERE id=$1`, id, key); err != nil {
				return err
			}
			g.ConfigKey = key
			// Receipt ownership is preserved for manual partitioning, but the
			// old configuration's healthy baseline cannot confirm this one.
			g.ReadyAt = 0
		} else {
			resumable, e := investigationRestartMatches(ctx, tx, g, key)
			if e != nil {
				return e
			}
			if resumable {
				if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET config_key=$2,revision=revision+1 WHERE id=$1`, id, key); err != nil {
					return err
				}
				g.ConfigKey = key
			} else {
				if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET config_key=$2,epoch_at=$3,generation=generation+1,ready_at=0,normal_since=0,normal_checkpoints='{}',revision=revision+1,reason='监控配置或会话变更，重新观察' WHERE id=$1`, id, key, now); err != nil {
					return err
				}
				return tx.Commit()
			}
		}
	}
	if !immediate && !fresh {
		// Retain the round while startup awaits fresh reports. A reporting gap
		// still fails continuity checks and cannot turn into timeout evidence.
		return finish("监控未启用、探针离线或数据过期")
	}
	allSuccess := true
	for _, p := range probes {
		allSuccess = allSuccess && p.Success
	}
	repair := g.ObservationRepairPending && g.Policy == "smart" && g.LifecycleRole == "ordinary" && g.RouteScope == "business"
	if !immediate && allSuccess && !repair {
		stage = "更新正常入口观察状态"
		for _, p := range probes {
			// A real latest success supersedes every earlier incident. Only this
			// branch can use one sample; failure evidence retains full history.
			samples, e := investigationSamplesLimit(ctx, tx, p.dispatchSplitCandidate, g.EpochAt, 1)
			if e != nil {
				return e
			}
			// A newer report can arrive between the state and history reads.
			// Use the full reconstruction unless this is the exact saved success.
			if len(samples) != 1 || !samples[0].Success || samples[0].Sequence != p.Sequence || samples[0].ReportedAt != p.Reported {
				samples, e = investigationSamples(ctx, tx, p.dispatchSplitCandidate, g.EpochAt)
				if e != nil {
					return e
				}
			}
			if _, e = loadInvestigationIncident(ctx, tx, g, p, samples); e != nil {
				return e
			}
		}
		var failedAt int64
		if err = tx.QueryRowContext(ctx, `SELECT delivery_failure_at FROM v2_dispatch_investigation_health WHERE id=1`).Scan(&failedAt); err != nil {
			return err
		}
		failedAt = max(failedAt, usersvc.InvestigationDeliveryFailureAt())
		s.dispatchHistoryMu.Lock()
		failedAt = max(failedAt, s.dispatchHistoryLastFailureAt)
		s.dispatchHistoryMu.Unlock()
		if failedAt >= g.EpochAt {
			if err = clearNormalObservation(ctx, tx, g.ID); err != nil {
				return err
			}
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
		if err = s.advanceNormalObservation(ctx, tx, &g, settings, probes); err != nil {
			return err
		}
		if !settings.LifecycleEnabled || g.Policy != "smart" {
			return finish("正常观察中")
		}
		if correctionPending != "" {
			// Preserve the pending roster correction and do not promote the
			// mixed stage while still advancing unaffected users' observation.
			return finish(correctionPending)
		}
		required := stableObserveSeconds
		if g.LifecycleRole == "stable" {
			required = whitelistObserveSeconds
		}
		if len(g.UserIDs) > 1 && g.LifecycleRole != "whitelist" && g.NormalSince > 0 && g.NormalObservedAt-g.NormalSince >= required {
			return s.promoteInvestigation(ctx, tx, g, entries, finish)
		}
		return finish(lifecycleNormalReason(g, now))
	}
	if !immediate && g.LifecycleRole != "ordinary" && !settings.LifecycleEnabled {
		return finish("老实人自动处理已关闭")
	}
	if !immediate && !repair && g.ReadyAt == 0 {
		return finish("新入口尚未确认正常，不按本轮失败筛选")
	}
	duration := int64(600)
	if immediate {
		duration = 0
	}
	var evidence investigationEvidence
	var reason string
	stage = "读取故障与拉取证据"
	if repair && !immediate {
		// Complete a proven historical non-recipient partition, not a new
		// failure diagnosis. Never fabricate a successful baseline or a cutoff.
		evidence = investigationEvidence{Mode: "observation_repair", CutoffSource: "original_unpulled_partition", Controls: map[int64][]string{}, Warnings: []string{"补完历史未拉取观察分支的健康入口分配，不按当前拉取记录重新筛人"}}
	} else if immediate {
		evidence, err = s.manualInvestigationEvidence(ctx, tx, g, probes)
	} else {
		evidence, reason, err = s.investigationEvidenceWithDuration(ctx, tx, g, probes, entries, duration)
	}
	if err != nil {
		return err
	}
	if reason != "" {
		return finish(reason)
	}
	if !immediate && !repair && evidence.First < max(g.ReadyAt, settings.ArmedAt) {
		return finish("故障起点早于有效观察期")
	}
	if err = clearNormalObservation(ctx, tx, g.ID); err != nil {
		return err
	}
	// Share limits across the whole immutable family and the previous splitter.
	if !immediate {
		var last, count int64
		if err = tx.QueryRowContext(ctx, `SELECT COALESCE(max(created_at),0) FROM v2_dispatch_investigation_event WHERE root_id=$1 AND kind IN('filtered','bisected','no_pulls','recovered','observation_repaired','whitelist_failed_over','whitelist_bisected')`, g.RootID).Scan(&last); err != nil {
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
		if err = tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM v2_dispatch_investigation_event WHERE kind IN('filtered','bisected','no_pulls','recovered','observation_repaired','whitelist_failed_over','whitelist_bisected') AND created_at>$1)+(SELECT count(*) FROM v2_dispatch_auto_split_operation WHERE status='succeeded' AND updated_at>$1)`, now-settings.GlobalWindowMinutes*60).Scan(&count); err != nil {
			return err
		}
		if count >= settings.GlobalMax {
			return finish("达到全局自动处理频率限制")
		}
	}
	if immediate {
		if err = investigationAudit(ctx, tx, g.RootID, g.ID, "manual_trigger", evidence.First, map[string]any{"host": g.Host, "revision": revision, "evidence": evidence}); err != nil {
			return err
		}
	}
	stage = "读取同根观察组"
	groups, err = readInvestigationGroupsWhere(ctx, tx, `g.active AND g.root_id=$1`, g.RootID)
	if err != nil {
		return err
	}
	groups = currentInvestigationGroups(groups, members)
	stage = "分组并分配备用入口"
	return s.applyInvestigation(ctx, tx, g, groups, evidence, entries, duration, finish)
}
