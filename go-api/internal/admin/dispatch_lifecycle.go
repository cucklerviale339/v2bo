package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"time"

	usersvc "forest/go-api/internal/user"
)

const stableObserveSeconds int64 = 3 * 24 * 60 * 60
const whitelistObserveSeconds int64 = 7 * 24 * 60 * 60

// Checkpoints make long observations durable without retaining ten days of
// raw probe samples. Unknown reporting intervals pause, rather than erase,
// accumulated evidence; confirmed continuous failures restart observation.
type normalCheckpoint struct{ Version, RunID, Sequence, ReportedAt int64 }

func normalContinuity(samples []DispatchHistorySample, p investigationProbe, previous normalCheckpoint) bool {
	if previous.ReportedAt == 0 || previous.Version != p.Version || previous.RunID != p.RunID {
		return false
	}
	newer := DispatchHistorySample{Version: p.Version, RunID: p.RunID, Sequence: p.Sequence, ReportedAt: p.Reported, Success: p.Success}
	for i, x := range samples {
		if !x.Success || x.Version != p.Version || x.RunID != p.RunID {
			return false
		}
		if i == 0 && (x.Sequence != p.Sequence || x.ReportedAt != p.Reported) {
			return false
		}
		if i > 0 && (newer.RecordedRestartBefore || newer.UnverifiedRestartBefore || !dispatchEvidenceFollows(newer, x, p.dispatchSplitCandidate) || newer.ReportedAt-x.ReportedAt > p.Interval+(p.Timeout+999)/1000+5) {
			return false
		}
		if x.Sequence == previous.Sequence && x.ReportedAt == previous.ReportedAt {
			return true
		}
		if x.ReportedAt < previous.ReportedAt {
			return false
		}
		newer = x
	}
	return false
}

// Stability tolerates a recovered short failure. Missing reports never earn
// observation time, but do not erase the valid observation before a restart.
// Confirmed failures invalidate the observation even if no spare IP was ready.
type observationPause struct{ From, To int64 }

func stabilityProgress(samples []DispatchHistorySample, p investigationProbe, old normalCheckpoint) ([]observationPause, int64) {
	if old.ReportedAt == 0 || p.Reported <= old.ReportedAt {
		return nil, 0
	}
	chronological := []DispatchHistorySample{}
	for i := len(samples) - 1; i >= 0; i-- {
		if samples[i].ReportedAt > old.ReportedAt {
			chronological = append(chronological, samples[i])
		}
	}
	pauses := []observationPause{}
	last := old.ReportedAt
	previous := DispatchHistorySample{Version: old.Version, RunID: p.RunID, Sequence: old.Sequence, ReportedAt: old.ReportedAt, Success: true}
	var failed, reset int64
	allowance := p.Interval + (p.Timeout+999)/1000 + 5
	for _, x := range chronological {
		if x.ReportedAt-last > allowance || x.RecordedRestartBefore || x.UnverifiedRestartBefore || !dispatchEvidenceFollows(x, previous, p.dispatchSplitCandidate) {
			pauses = append(pauses, observationPause{last, x.ReportedAt})
			failed = 0
		}
		if !x.Success {
			if failed == 0 {
				failed = x.ReportedAt
			}
			if x.ReportedAt-failed >= 600 {
				reset = x.ReportedAt
			}
		} else {
			failed = 0
		}
		last = x.ReportedAt
		previous = x
	}
	if last < p.Reported {
		pauses = append(pauses, observationPause{last, p.Reported})
	}
	return pauses, reset
}

func mergeObservationPauses(spans []observationPause) []observationPause {
	sort.Slice(spans, func(i, j int) bool { return spans[i].From < spans[j].From })
	out := []observationPause{}
	for _, x := range spans {
		if x.To <= x.From {
			continue
		}
		if len(out) > 0 && x.From <= out[len(out)-1].To {
			out[len(out)-1].To = max(out[len(out)-1].To, x.To)
		} else {
			out = append(out, x)
		}
	}
	return out
}

func (s *DBService) advanceNormalObservation(ctx context.Context, tx *sql.Tx, g *InvestigationGroup, settings InvestigationSettings, probes []investigationProbe) error {
	if !settings.LifecycleEnabled || g.Policy != "smart" {
		return nil
	}
	previous := map[int64]normalCheckpoint{}
	_ = json.Unmarshal(g.NormalCheckpoints, &previous)
	checkpoints := map[int64]normalCheckpoint{}
	pauses := []observationPause{}
	latest, reset := int64(0), int64(0)
	observed := int64(0)
	for _, p := range probes {
		old := previous[p.ProbeID]
		samples, err := investigationSamples(ctx, tx, p.dispatchSplitCandidate, old.ReportedAt)
		if err != nil {
			return err
		}
		gaps, fault := stabilityProgress(samples, p, old)
		pauses = append(pauses, gaps...)
		reset = max(reset, fault)
		latest = max(latest, p.Reported)
		if observed == 0 || p.Reported < observed {
			observed = p.Reported
		}
		checkpoints[p.ProbeID] = normalCheckpoint{p.Version, p.RunID, p.Sequence, p.Reported}
	}
	if g.NormalSince == 0 || reset > 0 || len(previous) != len(probes) {
		g.NormalSince = max(latest, max(g.EpochAt, settings.LifecycleStartedAt))
	} else {
		for _, gap := range mergeObservationPauses(pauses) {
			g.NormalSince += max(int64(0), gap.To-max(gap.From, g.NormalSince))
			// Shift each member only by their own intersection with the gap.
			// The checkpoint and these adjustments commit atomically.
			_, err := tx.ExecContext(ctx, `UPDATE v2_dispatch_stability_receipt d SET first_at=first_at+GREATEST(0,$3::bigint-GREATEST(first_at,$2::bigint)) WHERE host=$4 AND first_at<$3 AND EXISTS(SELECT 1 FROM v2_dispatch_investigation_member m WHERE m.group_id=$1 AND m.user_id=d.user_id AND m.origin_host=d.origin_host)`, g.ID, gap.From, gap.To, g.Host)
			if err != nil {
				return err
			}
		}
	}
	g.NormalSince = max(g.NormalSince, settings.LifecycleStartedAt)
	raw, _ := json.Marshal(checkpoints)
	g.NormalCheckpoints = raw
	g.NormalObservedAt = observed
	_, err := tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET normal_since=$2,normal_checkpoints=$3 WHERE id=$1`, g.ID, g.NormalSince, string(raw))
	return err
}

func clearNormalObservation(ctx context.Context, tx *sql.Tx, id int64) error {
	_, err := tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET normal_since=0,normal_checkpoints='{}' WHERE id=$1 AND (normal_since<>0 OR normal_checkpoints<>'{}'::jsonb)`, id)
	return err
}

// Recheck the source after allocation work. A probe may report failure while
// the transaction is preparing a promotion; never commit the earlier success
// snapshot as if it were still a complete normal observation.
func (s *DBService) verifyPromotionObservation(ctx context.Context, tx *sql.Tx, g InvestigationGroup) error {
	key, probes, fresh, err := investigationProbeConfig(ctx, tx, g.MonitorID)
	if err != nil {
		return err
	}
	if !fresh || key != g.ConfigKey {
		return fmt.Errorf("晋级期间监控配置或健康状态发生变化，等待重新观察")
	}
	previous := map[int64]normalCheckpoint{}
	if err = json.Unmarshal(g.NormalCheckpoints, &previous); err != nil {
		return err
	}
	for _, p := range probes {
		old := previous[p.ProbeID]
		samples, e := investigationSamples(ctx, tx, p.dispatchSplitCandidate, max(g.EpochAt, old.ReportedAt))
		if e != nil {
			return e
		}
		if s.dispatchProbeResetBlocked(p.ProbeID) || !p.Success || !normalContinuity(samples, p, old) {
			return fmt.Errorf("晋级期间出现失败或检测空档，等待重新观察")
		}
	}
	return nil
}

func lifecycleNormalReason(g InvestigationGroup, now int64) string {
	if g.LifecycleRole == "whitelist" {
		return "老实人，持续监控中"
	}
	if g.LifecycleRole == "stable" {
		return "稳定组，按个人拉取入口后再观察7天"
	}
	return "正常观察中，实际拉取满3天后进入稳定组"
}

// Check every actual node port using existing pool probe results. No new pool
// states, direct administrator-side dialing, or silent port substitution.
func (s *DBService) globalHostReady(ctx context.Context, tx *sql.Tx, host string) (bool, error) {
	// TCP reachability cannot prove the port-to-backend mapping. The operator
	// must first mark this IP as a verified full-site forwarder.
	var compatible bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v2_dispatch_check_target WHERE kind='pool' AND host=$1 AND enabled AND global_compatible)`, host).Scan(&compatible); err != nil {
		return false, err
	}
	if !compatible {
		return false, nil
	}
	ports, err := usersvc.ManagedDispatchPortsFrom(ctx, tx)
	if err != nil {
		return false, err
	}
	if len(ports) == 0 {
		return false, fmt.Errorf("没有启用的托管节点")
	}
	for _, port := range ports {
		var item DispatchPoolItem
		err = tx.QueryRowContext(ctx, `SELECT id,host,port,check_interval_sec,tcp_timeout_ms FROM v2_dispatch_check_target WHERE kind='pool' AND enabled AND host=$1 AND port=$2`, host, port).Scan(&item.ID, &item.IP, &item.Port, &item.CheckIntervalSec, &item.TCPTimeoutMS)
		if err == sql.ErrNoRows {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		item.Enabled = true
		rows, e := tx.QueryContext(ctx, `SELECT p.id,p.last_heartbeat_at,b.success,b.reported_at,COALESCE(b.streak,0) FROM v2_dns_probe p LEFT JOIN v2_dispatch_check_binding b ON b.probe_id=p.id AND b.target_id=$1 WHERE p.enabled=1`, item.ID)
		if e != nil {
			return false, e
		}
		now := time.Now().Unix()
		for rows.Next() {
			var st DispatchCheckState
			var hb, at sql.NullInt64
			var success sql.NullBool
			if e = rows.Scan(&st.ProbeID, &hb, &success, &at, &st.ConsecutiveSuccess); e != nil {
				break
			}
			st.Online = dnsProbeHeartbeatFresh(hb, now, defaultProbeOfflineSec)
			st.Stale = s.dispatchProbeResetBlocked(st.ProbeID) || !dispatchPoolStateFresh(at, now, item.CheckIntervalSec, item.TCPTimeoutMS)
			if success.Valid {
				v := success.Bool
				st.Success = &v
			}
			item.States = append(item.States, st)
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			return false, e
		}
		if _, ok := classifyDispatchPool(item); !ok {
			return false, nil
		}
	}
	return true, nil
}

func (s *DBService) lifecyclePool(ctx context.Context, tx *sql.Tx, g InvestigationGroup, refs map[string][]string, needed int) ([]DispatchPoolSave, error) {
	limit := needed
	if g.RouteScope == "global" {
		limit = 256
	}
	pool, err := s.dispatchSplitPoolLimit(ctx, tx, refs, dispatchSplitCandidate{ID: g.MonitorID}, false, nil, limit)
	if err != nil {
		return nil, err
	}
	out := []DispatchPoolSave{}
	for _, p := range pool {
		if g.RouteScope == "global" {
			ok, e := s.globalHostReady(ctx, tx, p.IP)
			if e != nil {
				return nil, e
			}
			if !ok {
				continue
			}
		}
		out = append(out, p)
		if len(out) == needed {
			break
		}
	}
	return out, nil
}

func hasOutsideExposure(ctx context.Context, tx *sql.Tx, g InvestigationGroup) (bool, error) {
	raw, _ := json.Marshal(investigationGroupIDs(g))
	var outside bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v2_dispatch_host_exposure WHERE host=$1 AND user_id NOT IN(SELECT value::bigint FROM jsonb_array_elements_text($2::jsonb)))`, g.Host, string(raw)).Scan(&outside)
	return outside, err
}

func hasOutsideDispatch(ctx context.Context, tx *sql.Tx, g InvestigationGroup, entries []usersvc.DispatchEntry) (bool, error) {
	inside := map[int64]bool{}
	for _, id := range investigationGroupIDs(g) {
		inside[id] = true
	}
	for _, entry := range entries {
		if entry.Host != g.Host {
			continue
		}
		ids, err := usersvc.DispatchAccountIDs(ctx, tx, entry)
		if err != nil {
			return false, err
		}
		for _, id := range ids {
			if !inside[id] {
				return true, nil
			}
		}
	}
	return false, nil
}

// Projection for a full-site move: remove these existing users from every
// prior endpoint, then assign one global endpoint. Other IDs stay unchanged.
func verifyGlobalInvestigationMove(before, after []usersvc.DispatchEntry, moves map[int64]string) error {
	return compareGlobalProjection(before, after, moves)
}

// compareGlobalProjection uses finite interval subtraction, retaining IDs that
// do not currently exist in the configured business ranges.
func compareGlobalProjection(before, after []usersvc.DispatchEntry, moves map[int64]string) error {
	expected := map[string][]splitEditSpan{}
	for _, e := range before {
		expected[e.Host] = splitEntrySpans(e)
	}
	for id, dest := range moves {
		found := false
		for host, spans := range expected {
			out := []splitEditSpan{}
			for _, sp := range spans {
				if id < sp.a || id > sp.b {
					out = append(out, sp)
					continue
				}
				found = true
				if sp.a < id {
					out = append(out, splitEditSpan{sp.a, id - 1})
				}
				if id < sp.b {
					out = append(out, splitEditSpan{id + 1, sp.b})
				}
			}
			expected[host] = out
		}
		if found {
			expected[dest] = append(expected[dest], splitEditSpan{id, id})
		}
	}
	got := map[string][]splitEditSpan{}
	for _, e := range after {
		got[e.Host] = splitEntrySpans(e)
	}
	canonical := func(m map[string][]splitEditSpan) map[string][]splitEditSpan {
		out := map[string][]splitEditSpan{}
		for host, spans := range m {
			sort.Slice(spans, func(i, j int) bool { return spans[i].a < spans[j].a })
			merged := []splitEditSpan{}
			for _, sp := range spans {
				if len(merged) > 0 && sp.a-1 <= merged[len(merged)-1].b {
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
	if !reflect.DeepEqual(canonical(expected), canonical(got)) {
		return fmt.Errorf("全站实际下发与预期名单不一致，已回滚")
	}
	return nil
}

// Promotions move the existing origin/member mapping. They never install a
// global '*' override, so other nodes and manual routing keep their behavior.
func (s *DBService) promoteInvestigation(ctx context.Context, tx *sql.Tx, g InvestigationGroup, before []usersvc.DispatchEntry, finish func(string) error) error {
	if g.RouteScope != "business" {
		return finish("旧全站分组仅保留原策略，不自动迁移")
	}
	if err := lockInvestigationAddresses(ctx, tx); err != nil {
		return err
	}
	current, members, err := usersvc.DispatchEntriesWithInvestigationMembersFrom(ctx, tx)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(before, current) {
		return finish("下发规则发生变化，等待重新确认")
	}
	actual := currentInvestigationGroups([]InvestigationGroup{g}, members)
	if len(actual) != 1 || !reflect.DeepEqual(actual[0].UserIDs, g.UserIDs) {
		return finish("分组实际成员发生变化，等待重新确认")
	}
	settings, err := readInvestigationSettings(ctx, tx, false)
	if err != nil {
		return err
	}
	role, name, required := "stable", "稳定组", stableObserveSeconds
	if g.LifecycleRole == "stable" {
		role, name, required = "whitelist", "老实人", whitelistObserveSeconds
	}
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT m.user_id FROM v2_dispatch_investigation_member m JOIN v2_user u ON u.id=m.user_id
JOIN v2_dispatch_stability_receipt d ON d.origin_host=m.origin_host AND d.user_id=m.user_id AND d.host=$2
WHERE m.group_id=$1 AND GREATEST(d.first_at,$3::bigint,$4::bigint)<=$5::bigint-$6::bigint
AND NOT EXISTS(SELECT 1 FROM v2_dispatch_investigation_member other JOIN v2_dispatch_investigation_group x ON x.id=other.group_id AND x.active
WHERE other.user_id=m.user_id AND x.id<>$1 AND (x.manual_only OR x.policy<>'smart' OR EXISTS(SELECT 1 FROM v2_dispatch_monitor_state st WHERE st.monitor_id=x.monitor_id AND NOT st.success)))
ORDER BY m.user_id`, g.ID, g.Host, g.NormalSince, settings.LifecycleStartedAt, min(time.Now().Unix(), g.NormalObservedAt), required)
	if err != nil {
		return err
	}
	eligible := map[int64]bool{}
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			break
		}
		eligible[id] = true
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	ids, _ := investigationPullPartition(investigationGroupIDs(g), eligible)
	if len(ids) == 0 {
		return finish(lifecycleNormalReason(g, time.Now().Unix()))
	}
	// A stage shares one concrete roster and entrance. Each member retains
	// their original origin_host selector even when coming from another root.
	targets, err := readInvestigationGroupsWhere(ctx, tx, `g.active AND g.route_scope='business' AND g.lifecycle_role=$1`, role)
	if err != nil {
		return err
	}
	targets = currentInvestigationGroups(targets, members)
	var target InvestigationGroup
	sharedHost := ""
	sharedMonitor := int64(0)
	var port int64
	if err = tx.QueryRowContext(ctx, `SELECT check_port FROM v2_dispatch_monitor WHERE id=$1`, g.MonitorID).Scan(&port); err != nil {
		return err
	}
	for _, x := range targets {
		if x.ManualOnly || x.Policy != "smart" || len(x.UserIDs) <= 1 {
			continue
		}
		if sharedHost != "" && sharedHost != x.Host {
			// A branch may already have failed over independently. Keep it
			// isolated and use only the established primary for new admissions.
			continue
		}
		sharedHost, sharedMonitor = x.Host, x.MonitorID
		var otherPort int64
		if err = tx.QueryRowContext(ctx, `SELECT check_port FROM v2_dispatch_monitor WHERE id=$1`, x.MonitorID).Scan(&otherPort); err != nil {
			return err
		}
		if otherPort != port {
			return finish("阶段入口检测端口不同，等待人工确认兼容性")
		}
		key, probes, fresh, e := investigationProbeConfig(ctx, tx, x.MonitorID)
		if e != nil {
			return e
		}
		if !fresh || (x.ConfigKey != "" && key != x.ConfigKey) {
			return finish("阶段入口未确认正常，暂停接收新成员")
		}
		for _, p := range probes {
			if !p.Success || s.dispatchProbeResetBlocked(p.ProbeID) {
				return finish("阶段入口异常，暂停接收新成员")
			}
		}
		if target.ID == 0 {
			target = x
		}
	}
	if sharedHost == g.Host {
		return finish("阶段入口必须与当前入口不同")
	}
	if target.ID == 0 && len(ids) < 2 {
		return finish("等待至少两名合格用户建立阶段分组")
	}
	if _, err = tx.ExecContext(ctx, `SAVEPOINT lifecycle_promote`); err != nil {
		return err
	}
	attempt := func() error {
		selected := []DispatchPoolSave{}
		refs, e := dispatchPoolReferences(ctx, tx)
		if e != nil {
			return e
		}
		if sharedHost == "" {
			selected, e = s.lifecyclePool(ctx, tx, g, refs, 1)
			if e != nil {
				return e
			}
			if len(selected) != 1 {
				return fmt.Errorf("等待同检测端口的健康未占用备用 IP")
			}
			sharedHost = selected[0].IP
			sharedMonitor, e = investigationCloneMonitor(ctx, tx, g.MonitorID, sharedHost)
			if e != nil {
				return e
			}
		}
		if target.ID == 0 {
			now := time.Now().Unix()
			if e = tx.QueryRowContext(ctx, `INSERT INTO v2_dispatch_investigation_group(root_id,parent_id,legacy_root_id,name,kind,host,monitor_id,epoch_at,created_at,route_scope,lifecycle_role,roster_frozen,reason) VALUES($1,$2,$3,$4,'observation',$5,$6,$7,$7,'business',$8,TRUE,'等待实际拉取新入口后开始观察') RETURNING id`, g.RootID, g.ID, g.LegacyRootID, name, sharedHost, sharedMonitor, now, role).Scan(&target.ID); e != nil {
				return e
			}
		} else {
			if _, e = tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET revision=revision+1 WHERE id=$1`, target.ID); e != nil {
				return e
			}
		}
		raw, _ := json.Marshal(ids)
		if _, e = tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_member SET group_id=$2 WHERE group_id=$1 AND user_id IN(SELECT value::bigint FROM jsonb_array_elements_text($3::jsonb))`, g.ID, target.ID, string(raw)); e != nil {
			return e
		}
		if len(selected) > 0 {
			locked, e := s.dispatchSplitPoolLimit(ctx, tx, refs, dispatchSplitCandidate{ID: g.MonitorID}, true, selected, 1)
			if e != nil {
				return e
			}
			if len(locked) != 1 {
				return fmt.Errorf("备用IP健康或占用状态发生变化")
			}
		}
		if _, e = tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET revision=revision+1,reason=$2 WHERE id=$1`, g.ID, "符合条件的实际用户已进入"+name); e != nil {
			return e
		}
		after, e := usersvc.DispatchEntriesFrom(ctx, tx)
		if e != nil {
			return e
		}
		moves := map[int64]string{}
		for _, id := range ids {
			moves[id] = sharedHost
		}
		if e = verifyInvestigationMove(before, after, g.Host, moves); e != nil {
			return e
		}
		if e = checkDispatchCapacity(ctx, tx); e != nil {
			return e
		}
		if e = s.verifyPromotionObservation(ctx, tx, g); e != nil {
			return e
		}
		if sharedMonitor > 0 && len(selected) == 0 {
			_, ps, fresh, e := investigationProbeConfig(ctx, tx, sharedMonitor)
			if e != nil {
				return e
			}
			if !fresh {
				return fmt.Errorf("阶段入口状态发生变化")
			}
			for _, p := range ps {
				if !p.Success {
					return fmt.Errorf("阶段入口状态发生变化")
				}
			}
		}
		kind := "stable_promoted"
		if role == "whitelist" {
			kind = "whitelist_promoted"
		}
		return investigationAudit(ctx, tx, g.RootID, g.ID, kind, 0, map[string]any{"before": g, "user_ids": ids, "host": sharedHost, "target_group_id": target.ID, "stage": role, "observation_seconds": required})
	}
	if err = attempt(); err != nil {
		if _, e := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT lifecycle_promote`); e != nil {
			return e
		}
		return finish(err.Error())
	}
	if _, err = tx.ExecContext(ctx, `RELEASE SAVEPOINT lifecycle_promote`); err != nil {
		return err
	}
	if err = tx.Commit(); err == nil {
		s.invalidateDispatchCatalog()
	}
	return err
}
