package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	usersvc "forest/go-api/internal/user"
)

type DispatchAutoSplitSettings struct {
	Enabled             bool  `json:"enabled"`
	EntryWindowMinutes  int64 `json:"entry_window_minutes"`
	GlobalWindowMinutes int64 `json:"global_window_minutes"`
	GlobalMax           int64 `json:"global_max"`
	ArmedAt             int64 `json:"armed_at"`
}
type DispatchAutoSplitOperation struct {
	ID          int64  `json:"id"`
	GroupID     int64  `json:"group_id"`
	RootGroupID int64  `json:"root_group_id"`
	ChildAID    int64  `json:"child_a_id"`
	ChildBID    int64  `json:"child_b_id"`
	Host        string `json:"host"`
	RootHost    string `json:"root_host"`
	ProbeID     int64  `json:"probe_id"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	RangeA      string `json:"range_a"`
	RangeB      string `json:"range_b"`
	IPA         string `json:"ip_a"`
	IPB         string `json:"ip_b"`
	CreatedAt   int64  `json:"created_at"`
	UpdatedAt   int64  `json:"updated_at"`
}
type DispatchAutoSplitView struct {
	Settings    DispatchAutoSplitSettings    `json:"settings"`
	Operations  []DispatchAutoSplitOperation `json:"operations"`
	Groups      []DispatchAutoSplitGroup     `json:"groups"`
	WorkerError string                       `json:"worker_error,omitempty"`
}

var dispatchAutoSplitSchema = []string{
	`CREATE TABLE IF NOT EXISTS v2_dispatch_auto_split_settings(id INTEGER PRIMARY KEY CHECK(id=1),enabled BOOLEAN NOT NULL DEFAULT FALSE,entry_window_minutes INTEGER NOT NULL DEFAULT 20 CHECK(entry_window_minutes BETWEEN 1 AND 10080),global_window_minutes INTEGER NOT NULL DEFAULT 60 CHECK(global_window_minutes BETWEEN 1 AND 10080),global_max INTEGER NOT NULL DEFAULT 3 CHECK(global_max BETWEEN 1 AND 100),armed_at BIGINT NOT NULL DEFAULT 0)`,
	`INSERT INTO v2_dispatch_auto_split_settings(id) VALUES(1) ON CONFLICT DO NOTHING`,
	`CREATE TABLE IF NOT EXISTS v2_dispatch_auto_split_group(id BIGSERIAL PRIMARY KEY,root_group_id BIGINT,parent_group_id BIGINT,monitor_id BIGINT NOT NULL UNIQUE,host TEXT NOT NULL,id_range TEXT NOT NULL,created_at BIGINT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS v2_dispatch_auto_split_operation(id BIGSERIAL PRIMARY KEY,monitor_id BIGINT NOT NULL,version BIGINT NOT NULL,probe_id BIGINT NOT NULL,run_id BIGINT NOT NULL,host TEXT NOT NULL,root_host TEXT NOT NULL,group_id BIGINT NOT NULL,root_group_id BIGINT NOT NULL,child_a_id BIGINT NOT NULL DEFAULT 0,child_b_id BIGINT NOT NULL DEFAULT 0,status TEXT NOT NULL CHECK(status IN('waiting','succeeded','cancelled')),reason TEXT NOT NULL DEFAULT '',range_a TEXT NOT NULL DEFAULT '',range_b TEXT NOT NULL DEFAULT '',ip_a TEXT NOT NULL DEFAULT '',ip_b TEXT NOT NULL DEFAULT '',created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL,UNIQUE(monitor_id,version,probe_id,run_id))`,
	`CREATE INDEX IF NOT EXISTS idx_dispatch_split_success ON v2_dispatch_auto_split_operation(status,updated_at DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_dispatch_split_lineage ON v2_dispatch_auto_split_operation(root_group_id,status,updated_at DESC)`,
	`ALTER TABLE v2_dispatch_auto_split_group ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 1`,
	`CREATE TABLE IF NOT EXISTS v2_dispatch_auto_split_cooldown(root_group_id BIGINT PRIMARY KEY,last_success_at BIGINT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS v2_dispatch_auto_split_edit(id BIGSERIAL PRIMARY KEY,before_data JSONB NOT NULL,after_data JSONB NOT NULL,created_at BIGINT NOT NULL)`,
}

func (s *DBService) ensureDispatchAutoSplitSchema(ctx context.Context) error {
	s.dispatchAutoSplitMu.Lock()
	defer s.dispatchAutoSplitMu.Unlock()
	if s.dispatchAutoSplitSchemaOK {
		return nil
	}
	if s.db == nil {
		return ErrUnavailable
	}
	for _, q := range dispatchAutoSplitSchema {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	s.dispatchAutoSplitSchemaOK = true
	return nil
}
func readDispatchAutoSplitSettings(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, lock bool) (DispatchAutoSplitSettings, error) {
	var v DispatchAutoSplitSettings
	sqlText := `SELECT enabled,entry_window_minutes,global_window_minutes,global_max,armed_at FROM v2_dispatch_auto_split_settings WHERE id=1`
	if lock {
		sqlText += ` FOR UPDATE`
	}
	err := q.QueryRowContext(ctx, sqlText).Scan(&v.Enabled, &v.EntryWindowMinutes, &v.GlobalWindowMinutes, &v.GlobalMax, &v.ArmedAt)
	return v, err
}
func (s *DBService) GetDispatchAutoSplit(ctx context.Context) (DispatchAutoSplitView, error) {
	out := DispatchAutoSplitView{Operations: []DispatchAutoSplitOperation{}}
	if err := s.ensureDispatchAutoSplitSchema(ctx); err != nil {
		return out, err
	}
	var err error
	out.Settings, err = readDispatchAutoSplitSettings(ctx, s.db, false)
	if err != nil {
		return out, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,host,root_host,group_id,root_group_id,child_a_id,child_b_id,probe_id,status,reason,range_a,range_b,ip_a,ip_b,created_at,updated_at FROM v2_dispatch_auto_split_operation ORDER BY updated_at DESC,id DESC LIMIT 50`)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var x DispatchAutoSplitOperation
		if err = rows.Scan(&x.ID, &x.Host, &x.RootHost, &x.GroupID, &x.RootGroupID, &x.ChildAID, &x.ChildBID, &x.ProbeID, &x.Status, &x.Reason, &x.RangeA, &x.RangeB, &x.IPA, &x.IPB, &x.CreatedAt, &x.UpdatedAt); err != nil {
			rows.Close()
			return out, err
		}
		out.Operations = append(out.Operations, x)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	out.Groups, err = readDispatchSplitGroups(ctx, s.db)
	if err != nil {
		return out, err
	}
	s.dispatchAutoSplitMu.Lock()
	out.WorkerError = s.dispatchAutoSplitLastError
	s.dispatchAutoSplitMu.Unlock()
	return out, nil
}
func (s *DBService) SaveDispatchAutoSplit(ctx context.Context, v DispatchAutoSplitSettings) error {
	if v.EntryWindowMinutes < 1 || v.EntryWindowMinutes > 10080 || v.GlobalWindowMinutes < 1 || v.GlobalWindowMinutes > 10080 || v.GlobalMax < 1 || v.GlobalMax > 100 {
		return fmt.Errorf("%w: 频率窗口为 1–10080 分钟，全局次数为 1–100", ErrDNSProbeInvalidRequest)
	}
	if err := s.ensureDispatchAutoSplitSchema(ctx); err != nil {
		return err
	}
	// A toggle or frequency edit arms a new ten-minute observation window.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_auto_split_settings SET enabled=$1,entry_window_minutes=$2,global_window_minutes=$3,global_max=$4,armed_at=$5 WHERE id=1`, v.Enabled, v.EntryWindowMinutes, v.GlobalWindowMinutes, v.GlobalMax, time.Now().Unix())
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_auto_split_operation SET status='cancelled',reason='设置已变更，取消旧观察并重新累计',updated_at=$1 WHERE status='waiting'`, time.Now().Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

type dispatchSplitCandidate struct {
	ID, Version, ProbeID, RunID, Sequence, Interval, Timeout, Reported int64
	Host, Error                                                        string
	Success                                                            bool
}

func dispatchSplitFresh(c dispatchSplitCandidate, now int64) bool {
	return dispatchPoolStateFresh(sql.NullInt64{Int64: c.Reported, Valid: c.Reported > 0}, now, c.Interval, c.Timeout)
}

// Every accepted result in the observation span must be a timeout. Missing
// samples, recovery, another error, old versions or sessions break the span.
func dispatchTimeoutSpan(samples []DispatchHistorySample, c dispatchSplitCandidate, now, armed int64) bool {
	if len(samples) < 2 || c.Success || c.Error != "timeout" || !dispatchSplitFresh(c, now) {
		return false
	}
	if samples[0].Sequence != c.Sequence || samples[0].ReportedAt != c.Reported {
		return false
	}
	previous := c.Reported
	for i, x := range samples {
		if x.Version != c.Version || x.RunID != c.RunID || (i > 0 && !dispatchEvidenceFollows(samples[i-1], x, c)) || x.Success || x.Error != "timeout" || x.ReportedAt < armed || x.ReportedAt > previous || !dispatchPoolStateFresh(sql.NullInt64{Int64: x.ReportedAt, Valid: true}, previous, c.Interval, c.Timeout) {
			return false
		}
		if now-x.ReportedAt >= 600 {
			return true
		}
		previous = x.ReportedAt
	}
	return false
}

func dispatchSplitStates(ctx context.Context, q dispatchQueryer) ([]dispatchSplitCandidate, error) {
	rows, err := q.QueryContext(ctx, `SELECT m.id,m.host,m.version,b.probe_id,b.run_id,st.sequence,m.check_interval_sec,m.tcp_timeout_ms,st.reported_at,st.success,st.error FROM v2_dispatch_monitor m JOIN v2_dispatch_monitor_probe b ON b.monitor_id=m.id JOIN v2_dispatch_monitor_state st ON st.monitor_id=m.id AND st.probe_id=b.probe_id AND st.version=m.version JOIN v2_dns_probe p ON p.id=b.probe_id WHERE m.enabled AND NOT m.deleted AND p.enabled=1 AND p.last_heartbeat_at>=$1 ORDER BY m.id,b.probe_id`, time.Now().Unix()-defaultProbeOfflineSec)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []dispatchSplitCandidate{}
	for rows.Next() {
		var c dispatchSplitCandidate
		if err = rows.Scan(&c.ID, &c.Host, &c.Version, &c.ProbeID, &c.RunID, &c.Sequence, &c.Interval, &c.Timeout, &c.Reported, &c.Success, &c.Error); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
func (s *DBService) splitEvidence(ctx context.Context, tx *sql.Tx, c dispatchSplitCandidate, entries []usersvc.DispatchEntry, armed, now int64) (bool, error) {
	// A lost optional history write invalidates continuity for all targets in
	// this process. Restart separately changes every live monitor session.
	s.dispatchHistoryMu.Lock()
	armed = max(armed, s.dispatchHistoryLastFailureAt)
	s.dispatchHistoryMu.Unlock()
	states, err := dispatchSplitStates(ctx, tx)
	if err != nil {
		return false, err
	}
	actual := map[string]bool{}
	for _, e := range entries {
		actual[e.Host] = true
	}
	found, peer := false, false
	for _, st := range states {
		if s.dispatchProbeResetBlocked(st.ProbeID) {
			continue
		}
		if st.ID == c.ID && st.ProbeID == c.ProbeID && st.Version == c.Version && st.RunID == c.RunID && st.Sequence == c.Sequence && st.Error == "timeout" && !st.Success && dispatchSplitFresh(st, now) {
			found = true
		}
		if st.Host != c.Host && actual[st.Host] && st.ProbeID == c.ProbeID && st.Success && dispatchSplitFresh(st, now) {
			peer = true
		}
	}
	if !found || !peer {
		return false, nil
	}
	from := max(armed, now-600-2*max(defaultProbeOfflineSec, 2*(c.Interval+(c.Timeout+999)/1000)))
	rows, err := tx.QueryContext(ctx, `SELECT payload FROM v2_dispatch_history WHERE source='entry' AND kind='sample' AND target_id=$1 AND probe_id=$2 AND version=$3 AND run_id=$4 AND created_at>=$5 ORDER BY sequence DESC LIMIT 2000`, c.ID, c.ProbeID, c.Version, c.RunID, from)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	samples := []DispatchHistorySample{}
	for rows.Next() {
		var raw []byte
		var x DispatchHistorySample
		if err = rows.Scan(&raw); err != nil {
			return false, err
		}
		if err = json.Unmarshal(raw, &x); err != nil {
			return false, err
		}
		samples = append(samples, x)
	}
	if err = rows.Err(); err != nil {
		return false, err
	}
	if !dispatchTimeoutSpan(samples, c, now, armed) {
		return false, nil
	}
	// An automatically assigned address must prove it worked in this exact
	// configuration/session before a later incident may consume more pool IPs.
	var descendant bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v2_dispatch_auto_split_group g WHERE g.monitor_id=$1 AND (g.parent_group_id IS NOT NULL OR EXISTS(SELECT 1 FROM v2_dispatch_auto_split_operation o WHERE o.status='succeeded' AND (o.child_a_id=g.id OR o.child_b_id=g.id))))`, c.ID).Scan(&descendant); err != nil {
		return false, err
	}
	if descendant {
		boundary := samples[0]
		for _, sample := range samples {
			boundary = sample
			if now-sample.ReportedAt >= 600 {
				break
			}
		}
		var healthyBefore bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v2_dispatch_history WHERE source='entry' AND kind='sample' AND target_id=$1 AND probe_id=$2 AND version=$3 AND run_id=$4 AND success=TRUE AND sequence<$5 AND created_at<=$6)`, c.ID, c.ProbeID, c.Version, c.RunID, boundary.Sequence, boundary.ReportedAt).Scan(&healthyBefore); err != nil {
			return false, err
		}
		return healthyBefore, nil
	}
	return true, nil
}

func (s *DBService) runDispatchAutoSplitCycle(ctx context.Context) error {
	if !s.dispatchHistoryEnabled {
		return nil
	}
	cycleCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	err := s.dispatchAutoSplitCycle(cycleCtx)
	s.dispatchAutoSplitMu.Lock()
	s.dispatchAutoSplitLastError = ""
	if err != nil {
		s.dispatchAutoSplitLastError = "自动二分检查失败，本轮未执行；请检查服务日志"
	}
	s.dispatchAutoSplitMu.Unlock()
	return err
}
func (s *DBService) dispatchAutoSplitCycle(ctx context.Context) error {
	if err := s.ensureDispatchAutoSplitSchema(ctx); err != nil {
		return err
	}
	settings, err := readDispatchAutoSplitSettings(ctx, s.db, false)
	if err != nil || !settings.Enabled {
		return err
	}
	if err = s.ensureDispatchMonitorSchema(ctx); err != nil {
		return err
	}
	if err = s.ensureDispatchHistorySchema(ctx); err != nil {
		return err
	}
	if err = s.ensureNodeAddressSchema(ctx); err != nil {
		return err
	}
	if _, err = s.db.ExecContext(ctx, `UPDATE v2_dispatch_auto_split_operation o SET status='cancelled',reason='入口恢复、监控变更或探针证据已失效，取消等待',updated_at=$1 WHERE o.status='waiting' AND NOT EXISTS(SELECT 1 FROM v2_dispatch_monitor m JOIN v2_dispatch_monitor_probe b ON b.monitor_id=m.id AND b.probe_id=o.probe_id JOIN v2_dns_probe p ON p.id=b.probe_id JOIN v2_dispatch_monitor_state st ON st.monitor_id=m.id AND st.probe_id=b.probe_id WHERE m.id=o.monitor_id AND m.enabled AND NOT m.deleted AND m.version=o.version AND st.version=m.version AND b.run_id=o.run_id AND p.enabled=1 AND p.last_heartbeat_at>=$1-90 AND NOT st.success AND st.error='timeout' AND st.reported_at>=$1-GREATEST(90,2*(m.check_interval_sec+(m.tcp_timeout_ms+999)/1000)))`, time.Now().Unix()); err != nil {
		return err
	}
	candidates, err := dispatchSplitStates(ctx, s.db)
	if err != nil {
		return err
	}
	s.dispatchAutoSplitMu.Lock()
	cursorID, cursorProbe := s.dispatchAutoSplitCursorID, s.dispatchAutoSplitCursorProbe
	s.dispatchAutoSplitMu.Unlock()
	index := sort.Search(len(candidates), func(i int) bool {
		return candidates[i].ID > cursorID || candidates[i].ID == cursorID && candidates[i].ProbeID > cursorProbe
	})
	candidates = append(append([]dispatchSplitCandidate{}, candidates[index:]...), candidates[:index]...)
	processed := 0
	for _, c := range candidates {
		if c.Success || c.Error != "timeout" || !dispatchSplitFresh(c, time.Now().Unix()) || s.dispatchProbeResetBlocked(c.ProbeID) {
			continue
		}
		s.dispatchAutoSplitMu.Lock()
		s.dispatchAutoSplitCursorID = c.ID
		s.dispatchAutoSplitCursorProbe = c.ProbeID
		s.dispatchAutoSplitMu.Unlock()
		changed, e := s.processDispatchAutoSplit(ctx, c)
		if e != nil {
			return e
		}
		processed++
		if changed || processed >= 20 {
			break
		}
	}
	return nil
}

func (s *DBService) processDispatchAutoSplit(ctx context.Context, c dispatchSplitCandidate) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout='500ms'; SET LOCAL statement_timeout='3s'`); err != nil {
		return false, err
	}
	settings, err := readDispatchAutoSplitSettings(ctx, tx, true)
	if err != nil || !settings.Enabled {
		return false, err
	}
	var locked bool
	if err = tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(7642309023)`).Scan(&locked); err != nil || !locked {
		return false, err
	}
	entries, err := usersvc.DispatchEntriesFrom(ctx, tx)
	if err != nil {
		return false, err
	}
	var entry *usersvc.DispatchEntry
	for i := range entries {
		if entries[i].Host == c.Host {
			entry = &entries[i]
			break
		}
	}
	if entry == nil {
		_, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_auto_split_operation SET status='cancelled',reason='入口已不参与实际下发，取消等待',updated_at=$2 WHERE monitor_id=$1 AND status='waiting'`, c.ID, time.Now().Unix())
		if err != nil {
			return false, err
		}
		return false, tx.Commit()
	}
	managed, err := investigationManaged(ctx, tx, *entry)
	if err != nil || managed {
		return false, err
	}
	var investigating bool
	if err = tx.QueryRowContext(ctx, `SELECT enabled FROM v2_dispatch_investigation_settings WHERE id=1`).Scan(&investigating); err != nil || investigating {
		return false, err
	}
	accountIDs, err := usersvc.DispatchAccountIDs(ctx, tx, *entry)
	if err != nil || len(accountIDs) <= 1 {
		return false, err
	}
	now := time.Now().Unix()
	confirmed, err := s.splitEvidence(ctx, tx, c, entries, settings.ArmedAt, now)
	if err != nil || !confirmed {
		return false, err
	}
	// Serialize all rule writers and pool deletions while re-projecting ownership.
	tables := []string{"v2_insider_rule", "v2_node_address_rule", "v2_node_address_group", "v2_node_address_binding"}
	for _, kind := range []string{"shadowsocks", "vmess", "trojan", "tuic", "hysteria", "vless", "anytls", "v2node"} {
		tables = append(tables, "v2_server_"+kind)
	}
	if _, err = tx.ExecContext(ctx, "LOCK TABLE "+strings.Join(tables, ",")+" IN SHARE ROW EXCLUSIVE MODE"); err != nil {
		return false, err
	}
	entries, err = usersvc.DispatchEntriesFrom(ctx, tx)
	if err != nil {
		return false, err
	}
	entry = nil
	for i := range entries {
		if entries[i].Host == c.Host {
			entry = &entries[i]
			break
		}
	}
	if entry == nil {
		_, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_auto_split_operation SET status='cancelled',reason='入口已不参与实际下发，取消等待',updated_at=$2 WHERE monitor_id=$1 AND status='waiting'`, c.ID, time.Now().Unix())
		if err != nil {
			return false, err
		}
		return false, tx.Commit()
	}
	confirmed, err = s.splitEvidence(ctx, tx, c, entries, settings.ArmedAt, time.Now().Unix())
	if err != nil || !confirmed {
		return false, err
	}
	var done bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v2_dispatch_auto_split_operation WHERE monitor_id=$1 AND version=$2 AND probe_id=$3 AND run_id=$4 AND status='succeeded')`, c.ID, c.Version, c.ProbeID, c.RunID).Scan(&done); err != nil || done {
		return false, err
	}
	var groupID, rootID int64
	var rootHost string
	err = tx.QueryRowContext(ctx, `SELECT g.id,g.root_group_id,r.host FROM v2_dispatch_auto_split_group g JOIN v2_dispatch_auto_split_group r ON r.id=g.root_group_id WHERE g.monitor_id=$1`, c.ID).Scan(&groupID, &rootID, &rootHost)
	if errors.Is(err, sql.ErrNoRows) {
		err = tx.QueryRowContext(ctx, `INSERT INTO v2_dispatch_auto_split_group(monitor_id,host,id_range,created_at) VALUES($1,$2,$3,$4) RETURNING id`, c.ID, c.Host, strings.Join(entry.UserIDRanges, ","), now).Scan(&groupID)
		if err == nil {
			_, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_auto_split_group SET root_group_id=id WHERE id=$1`, groupID)
		}
		rootID = groupID
		rootHost = c.Host
	}
	if err != nil {
		return false, err
	}
	op := DispatchAutoSplitOperation{GroupID: groupID, RootGroupID: rootID, Host: c.Host, RootHost: rootHost, ProbeID: c.ProbeID, Status: "waiting", CreatedAt: now, UpdatedAt: now}
	finish := func() (bool, error) {
		if op.Status == "succeeded" {
			if _, e := tx.ExecContext(ctx, `INSERT INTO v2_dispatch_auto_split_cooldown(root_group_id,last_success_at) VALUES($1,$2) ON CONFLICT(root_group_id) DO UPDATE SET last_success_at=GREATEST(v2_dispatch_auto_split_cooldown.last_success_at,EXCLUDED.last_success_at)`, rootID, now); e != nil {
				return false, e
			}
		}
		_, e := tx.ExecContext(ctx, `INSERT INTO v2_dispatch_auto_split_operation(monitor_id,version,probe_id,run_id,host,root_host,status,reason,range_a,range_b,ip_a,ip_b,created_at,updated_at,group_id,root_group_id,child_a_id,child_b_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,$14,$15,$16,$17) ON CONFLICT(monitor_id,version,probe_id,run_id) DO UPDATE SET root_group_id=EXCLUDED.root_group_id,group_id=EXCLUDED.group_id,root_host=EXCLUDED.root_host,status=EXCLUDED.status,reason=EXCLUDED.reason,range_a=EXCLUDED.range_a,range_b=EXCLUDED.range_b,ip_a=EXCLUDED.ip_a,ip_b=EXCLUDED.ip_b,child_a_id=EXCLUDED.child_a_id,child_b_id=EXCLUDED.child_b_id,updated_at=EXCLUDED.updated_at WHERE v2_dispatch_auto_split_operation.status<>'succeeded'`, c.ID, c.Version, c.ProbeID, c.RunID, op.Host, op.RootHost, op.Status, op.Reason, op.RangeA, op.RangeB, op.IPA, op.IPB, now, groupID, rootID, op.ChildAID, op.ChildBID)
		if e != nil {
			return false, e
		}
		if e = tx.Commit(); e != nil {
			return false, e
		}
		changed := op.Status == "succeeded"
		if changed {
			s.dispatchCacheMu.Lock()
			s.dispatchCachedHosts = nil
			s.dispatchCachedScopes = nil
			s.dispatchCacheAt = time.Time{}
			s.dispatchCacheMu.Unlock()
		}
		return changed, nil
	}
	a, b, ok := dispatchSplitRange(*entry)
	if !ok {
		op.Reason = "不是单个 ID 范围，或含具体 ID，跳过"
		return finish()
	}
	var count, last int64
	if err = tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM v2_dispatch_auto_split_operation WHERE status='succeeded' AND updated_at>$1)+(SELECT count(*) FROM v2_dispatch_investigation_event WHERE kind IN('filtered','bisected','no_pulls') AND created_at>$1)`, now-settings.GlobalWindowMinutes*60).Scan(&count); err != nil {
		return false, err
	}
	if count >= settings.GlobalMax {
		op.Reason = "达到全局自动二分频率上限，等待窗口释放"
		return finish()
	}
	if err = tx.QueryRowContext(ctx, `SELECT GREATEST(COALESCE((SELECT max(updated_at) FROM v2_dispatch_auto_split_operation WHERE status='succeeded' AND root_group_id=$1),0),COALESCE((SELECT last_success_at FROM v2_dispatch_auto_split_cooldown WHERE root_group_id=$1),0))`, rootID).Scan(&last); err != nil {
		return false, err
	}
	if last > 0 && now-last < settings.EntryWindowMinutes*60 {
		op.Reason = "同一入口及其二分后代仍在频率限制窗口内"
		return finish()
	}
	refs, err := dispatchPoolReferences(ctx, tx)
	if err != nil {
		return false, err
	}
	ips, err := s.dispatchSplitPool(ctx, tx, refs, c, false, nil)
	if err != nil {
		return false, err
	}
	if len(ips) != 2 {
		op.Reason = "同检测端口的健康未占用备用 IP 不足两个，未领取、未二分"
		return finish()
	}
	if _, err = tx.ExecContext(ctx, `SAVEPOINT auto_split_apply`); err != nil {
		return false, err
	}
	attempt := func() error {
		// Bind probes before locking pool targets: reporters lock probe then target.
		// Holding target locks while inserting FK bindings would invert that order.
		for index, ip := range ips {
			id, e := cloneDispatchPoolMonitor(ctx, tx, c.ID, ip.IP)
			if e != nil {
				return e
			}
			mid := a + (b-a)/2
			childRange := dispatchSplitSpan(a, mid)
			if index == 1 {
				childRange = dispatchSplitSpan(mid+1, b)
			}
			var childID int64
			if e := tx.QueryRowContext(ctx, `INSERT INTO v2_dispatch_auto_split_group(root_group_id,parent_group_id,monitor_id,host,id_range,created_at) VALUES($1,$2,$3,$4,$5,$6) RETURNING id`, rootID, groupID, id, ip.IP, childRange, now).Scan(&childID); e != nil {
				return e
			}
			if index == 0 {
				op.ChildAID = childID
			} else {
				op.ChildBID = childID
			}
		}
		fresh, e := s.splitEvidence(ctx, tx, c, entries, settings.ArmedAt, time.Now().Unix())
		if e != nil {
			return e
		}
		if !fresh {
			return fmt.Errorf("检测证据已变化，取消二分")
		}
		selected, e := s.dispatchSplitPool(ctx, tx, refs, c, true, ips)
		if e != nil {
			return e
		}
		if len(selected) != 2 {
			return fmt.Errorf("备用 IP 健康状态或引用已变化，取消二分")
		}
		if e = applyDispatchSplitRules(ctx, tx, entries, *entry, ips[0].IP, ips[1].IP, now); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE v2_dispatch_monitor SET enabled=FALSE,version=version+1 WHERE id=$1`, c.ID); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM v2_dispatch_monitor_probe WHERE monitor_id=$1`, c.ID); e != nil {
			return e
		}
		if e = checkDispatchCapacity(ctx, tx); e != nil {
			return e
		}
		return nil
	}
	if err = attempt(); err != nil {
		if _, e := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT auto_split_apply`); e != nil {
			return false, e
		}
		op.ChildAID = 0
		op.ChildBID = 0
		op.Reason = err.Error()
	} else {
		op.Status = "succeeded"
		op.Reason = "持续超时满 10 分钟，且同探针其他入口正常；两个新 IP 已按 ID 范围二分下发"
		op.IPA = ips[0].IP
		op.IPB = ips[1].IP
		mid := a + (b-a)/2
		op.RangeA = dispatchSplitSpan(a, mid)
		op.RangeB = dispatchSplitSpan(mid+1, b)
	}
	if _, err = tx.ExecContext(ctx, `RELEASE SAVEPOINT auto_split_apply`); err != nil {
		return false, err
	}
	return finish()
}

func (s *DBService) dispatchSplitPool(ctx context.Context, tx *sql.Tx, refs map[string][]string, c dispatchSplitCandidate, lock bool, selected []DispatchPoolSave) ([]DispatchPoolSave, error) {
	return s.dispatchSplitPoolLimit(ctx, tx, refs, c, lock, selected, 2)
}

func (s *DBService) dispatchSplitPoolLimit(ctx context.Context, tx *sql.Tx, refs map[string][]string, c dispatchSplitCandidate, lock bool, selected []DispatchPoolSave, limit int) ([]DispatchPoolSave, error) {
	// The port is only a check prerequisite; subscription ports are never changed.
	var port int64
	if err := tx.QueryRowContext(ctx, `SELECT check_port FROM v2_dispatch_monitor WHERE id=$1`, c.ID).Scan(&port); err != nil {
		return nil, err
	}
	items := selected
	if !lock {
		// Honor operator priority, then prefer an unused entrance over recycling
		// one that was recently exposed to another group. Old monitors are a
		// preference, never a permanent reservation of an otherwise healthy IP.
		rows, err := tx.QueryContext(ctx, `SELECT t.id,t.host,t.port,t.check_interval_sec,t.tcp_timeout_ms FROM v2_dispatch_check_target t WHERE t.kind='pool' AND t.enabled AND t.port=$1 ORDER BY t.sort,EXISTS(SELECT 1 FROM v2_dispatch_monitor m WHERE m.host=t.host),t.id`, port)
		if err != nil {
			return nil, err
		}
		items = []DispatchPoolSave{}
		for rows.Next() {
			var x DispatchPoolSave
			if err = rows.Scan(&x.ID, &x.IP, &x.Port, &x.CheckIntervalSec, &x.TCPTimeoutMS); err != nil {
				rows.Close()
				return nil, err
			}
			items = append(items, x)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	} else {
		items = append([]DispatchPoolSave{}, items...)
		sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	}
	out := []DispatchPoolSave{}
	seen := map[string]bool{}
	for _, item := range items {
		if len(refs[item.IP]) > 0 || seen[item.IP] {
			continue
		}
		if lock {
			var enabled bool
			var ip string
			err := tx.QueryRowContext(ctx, `SELECT host,port,enabled,check_interval_sec,tcp_timeout_ms FROM v2_dispatch_check_target WHERE id=$1 AND kind='pool' FOR UPDATE`, item.ID).Scan(&ip, &item.Port, &enabled, &item.CheckIntervalSec, &item.TCPTimeoutMS)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if !enabled || ip != item.IP || item.Port != port {
				continue
			}
		}
		rows, err := tx.QueryContext(ctx, `SELECT p.id,p.last_heartbeat_at,b.success,b.reported_at,COALESCE(b.streak,0) FROM v2_dns_probe p LEFT JOIN v2_dispatch_check_binding b ON b.probe_id=p.id AND b.target_id=$1 WHERE p.enabled=1`, item.ID)
		if err != nil {
			return nil, err
		}
		x := DispatchPoolItem{DispatchPoolSave: item}
		x.Enabled = true
		now := time.Now().Unix()
		for rows.Next() {
			var st DispatchCheckState
			var hb, at sql.NullInt64
			var success sql.NullBool
			if err = rows.Scan(&st.ProbeID, &hb, &success, &at, &st.ConsecutiveSuccess); err != nil {
				break
			}
			st.Online = dnsProbeHeartbeatFresh(hb, now, defaultProbeOfflineSec)
			st.Stale = s.dispatchProbeResetBlocked(st.ProbeID) || !dispatchPoolStateFresh(at, now, item.CheckIntervalSec, item.TCPTimeoutMS)
			if success.Valid {
				v := success.Bool
				st.Success = &v
			}
			x.States = append(x.States, st)
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return nil, err
		}
		if _, available := classifyDispatchPool(x); available {
			out = append(out, item)
			seen[item.IP] = true
			if len(out) == limit {
				break
			}
		}
	}
	return out, nil
}
