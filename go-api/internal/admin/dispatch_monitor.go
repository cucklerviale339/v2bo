package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"forest/go-api/internal/platform/addrutil"
	usersvc "forest/go-api/internal/user"
)

type DispatchMonitorSaveRequest struct {
	Host             string  `json:"host"`
	CheckPort        int64   `json:"check_port"`
	Enabled          bool    `json:"enabled"`
	CheckIntervalSec int64   `json:"check_interval_sec"`
	TCPTimeoutMS     int64   `json:"tcp_timeout_ms"`
	ProbeIDs         []int64 `json:"probe_ids"`
}

type DispatchMonitor struct {
	usersvc.DispatchEntry
	ID               int64                  `json:"id"`
	CheckPort        int64                  `json:"check_port"`
	Enabled          bool                   `json:"enabled"`
	Deleted          bool                   `json:"deleted"`
	CheckIntervalSec int64                  `json:"check_interval_sec"`
	TCPTimeoutMS     int64                  `json:"tcp_timeout_ms"`
	ProbeIDs         []int64                `json:"probe_ids"`
	States           []DispatchMonitorState `json:"states"`
}

type DispatchMonitorState struct {
	ProbeID    int64  `json:"probe_id"`
	ProbeName  string `json:"probe_name"`
	Online     bool   `json:"online"`
	Stale      bool   `json:"stale"`
	Success    *bool  `json:"success"`
	LatencyMS  *int64 `json:"latency_ms"`
	Error      string `json:"error"`
	ResolvedIP string `json:"resolved_ip"`
	ReportedAt *int64 `json:"reported_at"`
}

func (s *DBService) ensureDispatchMonitorSchema(ctx context.Context) error {
	if err := s.ensureDNSFailoverSchema(ctx); err != nil {
		return err
	}
	s.dispatchEnsureMu.Lock()
	defer s.dispatchEnsureMu.Unlock()
	if s.dispatchSchemaOK {
		return nil
	}
	for _, statement := range append([]string{
		`CREATE TABLE IF NOT EXISTS v2_dispatch_monitor (
id BIGSERIAL PRIMARY KEY, host VARCHAR(253) NOT NULL UNIQUE,
check_port INTEGER NOT NULL CHECK (check_port BETWEEN 1 AND 65535), enabled BOOLEAN NOT NULL DEFAULT FALSE,
check_interval_sec INTEGER NOT NULL CHECK(check_interval_sec BETWEEN 1 AND 86400),
tcp_timeout_ms INTEGER NOT NULL CHECK(tcp_timeout_ms BETWEEN 1 AND 60000), version BIGINT NOT NULL DEFAULT 1)`,
		`ALTER TABLE v2_dispatch_monitor ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT FALSE`,
		`CREATE TABLE IF NOT EXISTS v2_dispatch_monitor_probe (
monitor_id BIGINT NOT NULL REFERENCES v2_dispatch_monitor(id) ON DELETE CASCADE,
probe_id BIGINT NOT NULL REFERENCES v2_dns_probe(id) ON DELETE CASCADE,
run_id BIGINT NOT NULL DEFAULT 1,
PRIMARY KEY(monitor_id,probe_id))`,
		`CREATE TABLE IF NOT EXISTS v2_dispatch_monitor_state (
monitor_id BIGINT NOT NULL, probe_id BIGINT NOT NULL, version BIGINT NOT NULL,
sequence BIGINT NOT NULL, success BOOLEAN NOT NULL, latency_ms INTEGER, error TEXT NOT NULL DEFAULT '',
resolved_ip TEXT NOT NULL DEFAULT '', reported_at BIGINT NOT NULL,
PRIMARY KEY(monitor_id,probe_id),
FOREIGN KEY(monitor_id,probe_id) REFERENCES v2_dispatch_monitor_probe(monitor_id,probe_id) ON DELETE CASCADE)`,
	}, dispatchCheckSchema...) {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize dispatch monitoring: %w", err)
		}
	}
	// Every service process starts a fresh auxiliary session. A deferred reset
	// cannot be lost across a restart and then revive queued old observations.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_monitor_probe SET run_id=run_id+1`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM v2_dispatch_monitor_state`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_check_binding b SET session=session+1,sequence=0,success=NULL,latency_ms=NULL,error='',resolved_ip='',streak=0,reported_at=NULL FROM v2_dispatch_check_target t WHERE b.target_id=t.id AND (t.kind='pool' OR b.reported_at IS NULL)`); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.dispatchSchemaOK = true
	return nil
}

func (s *DBService) dispatchEntries(ctx context.Context) ([]usersvc.DispatchEntry, error) {
	if s.dispatchCatalog == nil {
		return nil, ErrUnavailable
	}
	return s.dispatchCatalog.DispatchEntries(ctx)
}

func (s *DBService) ListDispatchMonitors(ctx context.Context) ([]DispatchMonitor, error) {
	return s.listDispatchMonitors(ctx, false)
}

func (s *DBService) ListDispatchMonitorsIncludingDeleted(ctx context.Context) ([]DispatchMonitor, error) {
	return s.listDispatchMonitors(ctx, true)
}

func (s *DBService) listDispatchMonitors(ctx context.Context, includeDeleted bool) ([]DispatchMonitor, error) {
	if err := s.ensureDispatchMonitorSchema(ctx); err != nil {
		return nil, err
	}
	entries, err := s.dispatchEntries(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]DispatchMonitor, 0, len(entries))
	byHost := make(map[string]int, len(entries))
	byID := make(map[int64]int)
	for _, entry := range entries {
		byHost[entry.Host] = len(result)
		result = append(result, DispatchMonitor{DispatchEntry: entry, CheckPort: 443, CheckIntervalSec: 30, TCPTimeoutMS: 3000, ProbeIDs: []int64{}, States: []DispatchMonitorState{}})
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,host,check_port,enabled,check_interval_sec,tcp_timeout_ms,deleted FROM v2_dispatch_monitor ORDER BY id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var m DispatchMonitor
		var host string
		if err := rows.Scan(&m.ID, &host, &m.CheckPort, &m.Enabled, &m.CheckIntervalSec, &m.TCPTimeoutMS, &m.Deleted); err != nil {
			rows.Close()
			return nil, err
		}
		if i, ok := byHost[host]; ok {
			m.DispatchEntry = result[i].DispatchEntry
			m.ProbeIDs = []int64{}
			m.States = []DispatchMonitorState{}
			result[i] = m
			byID[m.ID] = i
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	rows, err = s.db.QueryContext(ctx, `SELECT b.monitor_id,p.id,p.name,p.enabled,p.last_heartbeat_at,
st.success,st.latency_ms,COALESCE(st.error,''),COALESCE(st.resolved_ip,''),st.reported_at
FROM v2_dispatch_monitor_probe b JOIN v2_dns_probe p ON p.id=b.probe_id
JOIN v2_dispatch_monitor m ON m.id=b.monitor_id
LEFT JOIN v2_dispatch_monitor_state st ON st.monitor_id=b.monitor_id AND st.probe_id=b.probe_id AND st.version=m.version
ORDER BY b.monitor_id,p.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now().Unix()
	for rows.Next() {
		var id, enabled int64
		var state DispatchMonitorState
		var heartbeat, reported, latency sql.NullInt64
		var success sql.NullBool
		if err := rows.Scan(&id, &state.ProbeID, &state.ProbeName, &enabled, &heartbeat, &success, &latency, &state.Error, &state.ResolvedIP, &reported); err != nil {
			return nil, err
		}
		i, ok := byID[id]
		if !ok {
			continue
		}
		m := &result[i]
		m.ProbeIDs = append(m.ProbeIDs, state.ProbeID)
		state.Online = enabled == 1 && dnsProbeHeartbeatFresh(heartbeat, now, defaultProbeOfflineSec)
		state.Stale = s.dispatchProbeResetBlocked(state.ProbeID) || !m.Enabled || !state.Online || !dnsFailoverProbeStateFresh(reported, now, m.CheckIntervalSec, m.TCPTimeoutMS, max(defaultProbeOfflineSec, 2*m.CheckIntervalSec+(m.TCPTimeoutMS+999)/1000))
		if reported.Valid {
			v := reported.Int64
			state.ReportedAt = &v
		}
		if !state.Stale && success.Valid {
			v := success.Bool
			state.Success = &v
		}
		if !state.Stale && latency.Valid {
			v := latency.Int64
			state.LatencyMS = &v
		}
		m.States = append(m.States, state)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !includeDeleted {
		visible := make([]DispatchMonitor, 0, len(result))
		for _, monitor := range result {
			if !monitor.Deleted {
				visible = append(visible, monitor)
			}
		}
		return visible, nil
	}
	return result, nil
}

func (s *DBService) SaveDispatchMonitor(ctx context.Context, req DispatchMonitorSaveRequest) error {
	if err := normalizeDispatchMonitorSave(&req); err != nil {
		return err
	}
	if err := s.ensureDispatchMonitorSchema(ctx); err != nil {
		return err
	}
	entries, err := s.dispatchEntries(ctx)
	if err != nil {
		return err
	}
	found := false
	for _, e := range entries {
		if e.Host == req.Host {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("%w: 该入口已不在当前节点地址配置中，请刷新", ErrDNSProbeInvalidRequest)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(7642309023)`); err != nil {
		return err
	}
	for _, id := range req.ProbeIDs {
		var enabled int64
		err := tx.QueryRowContext(ctx, `SELECT enabled FROM v2_dns_probe WHERE id=$1 FOR SHARE`, id).Scan(&enabled)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && enabled != 1) {
			return fmt.Errorf("%w: 请选择已启用的探针", ErrDNSProbeInvalidRequest)
		}
		if err != nil {
			return err
		}
	}
	var id int64
	err = tx.QueryRowContext(ctx, `INSERT INTO v2_dispatch_monitor(host,check_port,enabled,check_interval_sec,tcp_timeout_ms)
VALUES($1,$2,$3,$4,$5) ON CONFLICT(host) DO UPDATE SET check_port=EXCLUDED.check_port,enabled=EXCLUDED.enabled,
check_interval_sec=EXCLUDED.check_interval_sec,tcp_timeout_ms=EXCLUDED.tcp_timeout_ms,deleted=FALSE,version=v2_dispatch_monitor.version+1 RETURNING id`, req.Host, req.CheckPort, req.Enabled, req.CheckIntervalSec, req.TCPTimeoutMS).Scan(&id)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM v2_dispatch_monitor_probe WHERE monitor_id=$1`, id); err != nil {
		return err
	}
	for _, probeID := range req.ProbeIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO v2_dispatch_monitor_probe(monitor_id,probe_id) VALUES($1,$2)`, id, probeID); err != nil {
			return err
		}
	}
	if req.Enabled {
		if err = checkDispatchCapacity(ctx, tx); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func normalizeDispatchMonitorSave(req *DispatchMonitorSaveRequest) error {
	req.Host = normalizeDispatchMonitorHost(req.Host)
	if !addrutil.IsIPOrHostname(req.Host) || req.CheckPort < 1 || req.CheckPort > 65535 || req.CheckIntervalSec < 1 || req.CheckIntervalSec > 86400 || req.TCPTimeoutMS < 1 || req.TCPTimeoutMS > 60000 || len(req.ProbeIDs) > 500 {
		return fmt.Errorf("%w: 请检查入口、端口和探测策略", ErrDNSProbeInvalidRequest)
	}
	seen := make(map[int64]bool)
	ids := make([]int64, 0, len(req.ProbeIDs))
	for _, id := range req.ProbeIDs {
		if id <= 0 {
			return fmt.Errorf("%w: 探针 ID 无效", ErrDNSProbeInvalidRequest)
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if req.Enabled && len(ids) == 0 {
		return fmt.Errorf("%w: 启用监控前请选择探针", ErrDNSProbeInvalidRequest)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	req.ProbeIDs = ids
	return nil
}

func normalizeDispatchMonitorHost(host string) string {
	host = strings.TrimSpace(host)
	if address, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && address.Zone() == "" {
		return address.String()
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// Keep a tombstone because the address inventory is derived from subscriptions.
// Removing only the row would immediately recreate an unconfigured candidate.
func (s *DBService) DeleteDispatchMonitors(ctx context.Context, hosts []string) error {
	if len(hosts) == 0 || len(hosts) > 500 {
		return fmt.Errorf("%w: 请选择 1 至 500 个入口", ErrDNSProbeInvalidRequest)
	}
	normalized := make(map[string]bool, len(hosts))
	for _, host := range hosts {
		host = normalizeDispatchMonitorHost(host)
		if !addrutil.IsIPOrHostname(host) {
			return fmt.Errorf("%w: 入口地址无效", ErrDNSProbeInvalidRequest)
		}
		normalized[host] = true
	}
	if err := s.ensureDispatchMonitorSchema(ctx); err != nil {
		return err
	}
	entries, err := s.dispatchEntries(ctx)
	if err != nil {
		return err
	}
	current := make(map[string]bool, len(entries))
	for _, entry := range entries {
		current[entry.Host] = true
	}
	ordered := make([]string, 0, len(normalized))
	for host := range normalized {
		if !current[host] {
			return fmt.Errorf("%w: 该入口已不在当前节点地址配置中，请刷新", ErrDNSProbeInvalidRequest)
		}
		ordered = append(ordered, host)
	}
	sort.Strings(ordered)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(7642309023)`); err != nil {
		return err
	}
	// Result batches lock monitors by ID. Acquire existing rows in that same
	// order before changing any of them, regardless of the host display order.
	locked, err := tx.QueryContext(ctx, `SELECT id FROM v2_dispatch_monitor WHERE host=ANY($1) ORDER BY id FOR UPDATE`, ordered)
	if err != nil {
		return err
	}
	for locked.Next() {
		var id int64
		if err = locked.Scan(&id); err != nil {
			locked.Close()
			return err
		}
	}
	if err = locked.Err(); err != nil {
		locked.Close()
		return err
	}
	locked.Close()
	for _, host := range ordered {
		var id int64
		if err = tx.QueryRowContext(ctx, `INSERT INTO v2_dispatch_monitor(host,check_port,enabled,check_interval_sec,tcp_timeout_ms,deleted)
VALUES($1,443,FALSE,30,3000,TRUE) ON CONFLICT(host) DO UPDATE SET enabled=FALSE,deleted=TRUE,version=v2_dispatch_monitor.version+1 RETURNING id`, host).Scan(&id); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM v2_dispatch_monitor_probe WHERE monitor_id=$1`, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Negative target IDs keep monitoring separate from DNS failover target IDs.
// Existing probe auth, TCP checks and result transport are shared.
func (s *DBService) ListDispatchProbeTasks(ctx context.Context, probeID int64) ([]DNSProbeTask, error) {
	if err := s.ensureDispatchMonitorSchema(ctx); err != nil {
		return nil, err
	}
	if err := s.checkDispatchProbeReset(ctx, probeID); err != nil {
		return nil, err
	}
	hosts, err := s.dispatchTaskHosts(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT m.id,m.host,m.check_port,m.check_interval_sec,m.tcp_timeout_ms,m.version,b.run_id
FROM v2_dispatch_monitor m JOIN v2_dispatch_monitor_probe b ON b.monitor_id=m.id
JOIN v2_dns_probe p ON p.id=b.probe_id WHERE b.probe_id=$1 AND p.enabled=1 AND m.enabled=TRUE AND m.deleted=FALSE ORDER BY m.id`, probeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tasks := make([]DNSProbeTask, 0)
	for rows.Next() {
		var task DNSProbeTask
		if err := rows.Scan(&task.TargetID, &task.CheckHost, &task.CheckPort, &task.CheckIntervalSec, &task.TCPTimeoutMS, &task.TargetVersion, &task.RunID); err != nil {
			return nil, err
		}
		if hosts[task.CheckHost] {
			task.TargetID = -task.TargetID
			tasks = append(tasks, task)
		}
	}
	return tasks, rows.Err()
}

func (s *DBService) ReportDispatchProbeResults(ctx context.Context, probeID int64, request DNSProbeResultsRequest) (DNSProbeReportResult, error) {
	summary := DNSProbeReportResult{GroupIDs: []int64{}}
	if probeID <= 0 {
		return summary, ErrDNSProbeUnauthorized
	}
	if len(request.Results) > maxDNSProbeResultBatch {
		return summary, ErrDNSProbeInvalidRequest
	}
	// Validate a copy using the existing field limits; only this task namespace
	// permits negative IDs. The config version also rejects queued old results.
	validated := DNSProbeResultsRequest{Results: append([]DNSProbeResult{}, request.Results...)}
	for i, r := range validated.Results {
		if r.TargetID >= 0 || r.TargetID == math.MinInt64 || r.TargetVersion <= 0 || r.RunID <= 0 {
			return summary, ErrDNSProbeInvalidRequest
		}
		validated.Results[i].TargetID = -r.TargetID
	}
	if err := normalizeDNSProbeResultsRequest(&validated); err != nil {
		return summary, err
	}
	// A batch may arrive in arbitrary network order. A stable ID order avoids
	// cycles with bulk deletion while preserving sequence order for one target.
	sort.SliceStable(validated.Results, func(i, j int) bool {
		return validated.Results[i].TargetID < validated.Results[j].TargetID
	})
	if err := s.ensureDispatchMonitorSchema(ctx); err != nil {
		return summary, err
	}
	if err := s.checkDispatchProbeReset(ctx, probeID); err != nil {
		return summary, err
	}
	history := s.prepareDispatchHistory(ctx)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return summary, err
	}
	defer tx.Rollback()
	var enabled int64
	var heartbeat sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT enabled,last_heartbeat_at FROM v2_dns_probe WHERE id=$1 FOR UPDATE`, probeID).Scan(&enabled, &heartbeat); errors.Is(err, sql.ErrNoRows) || (err == nil && enabled != 1) {
		return summary, ErrDNSProbeUnauthorized
	} else if err != nil {
		return summary, err
	}
	now := time.Now().Unix()
	if s.dispatchProbeResetBlocked(probeID) {
		return summary, ErrDNSProbeHeartbeatRequired
	}
	if !dnsProbeHeartbeatFresh(heartbeat, now, defaultProbeOfflineSec) {
		return summary, ErrDNSProbeHeartbeatRequired
	}
	for _, r := range validated.Results {
		sequence, err := dispatchResultSequence(r)
		if err != nil {
			return summary, err
		}
		var version, runID int64
		err = tx.QueryRowContext(ctx, `SELECT m.version,b.run_id FROM v2_dispatch_monitor m JOIN v2_dispatch_monitor_probe b ON b.monitor_id=m.id WHERE m.id=$1 AND b.probe_id=$2 AND m.enabled=TRUE AND m.deleted=FALSE FOR SHARE OF m,b`, r.TargetID, probeID).Scan(&version, &runID)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && (version != r.TargetVersion || runID != r.RunID)) {
			summary.Skipped++
			continue
		}
		if err != nil {
			return summary, err
		}
		values := dnsProbeStateWriteValues(r)
		result, err := tx.ExecContext(ctx, `INSERT INTO v2_dispatch_monitor_state(monitor_id,probe_id,version,sequence,success,latency_ms,error,resolved_ip,reported_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(monitor_id,probe_id) DO UPDATE SET version=EXCLUDED.version,sequence=EXCLUDED.sequence,
success=EXCLUDED.success,latency_ms=EXCLUDED.latency_ms,error=EXCLUDED.error,resolved_ip=EXCLUDED.resolved_ip,reported_at=EXCLUDED.reported_at
WHERE v2_dispatch_monitor_state.version<>EXCLUDED.version OR v2_dispatch_monitor_state.sequence<EXCLUDED.sequence`, r.TargetID, probeID, version, sequence, *r.Success, values.Latency, values.Error, r.ResolvedIP, now)
		if err != nil {
			return summary, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return summary, err
		}
		if n > 0 {
			summary.Accepted++
			history.add("entry", probeID, r, now, 0)
		} else {
			summary.Duplicates++
		}
	}
	s.persistDispatchHistory(ctx, tx, history)
	if err := tx.Commit(); err != nil {
		return summary, err
	}
	return summary, nil
}

func dispatchResultSequence(result DNSProbeResult) (int64, error) {
	index := strings.LastIndexByte(result.ResultID, '-')
	if index < 0 {
		return 0, ErrDNSProbeInvalidRequest
	}
	sequence, err := strconv.ParseInt(result.ResultID[index+1:], 10, 64)
	if err != nil || sequence <= 0 {
		return 0, ErrDNSProbeInvalidRequest
	}
	return sequence, nil
}

// A probe reconnect starts a new run so queued results from its previous
// session cannot revive a healthy state after the old state was cleared.
func resetDispatchProbeState(ctx context.Context, tx *sql.Tx, probeID int64) error {
	_, err := tx.ExecContext(ctx, `WITH bumped AS (
UPDATE v2_dispatch_monitor_probe SET run_id=run_id+1 WHERE probe_id=$1 RETURNING monitor_id)
 , reset_checks AS (
 UPDATE v2_dispatch_check_binding b SET session=session+1,sequence=0,success=NULL,latency_ms=NULL,
 error='',resolved_ip='',streak=0,reported_at=NULL
 FROM v2_dispatch_check_target t WHERE b.target_id=t.id AND b.probe_id=$1
 AND (t.kind='pool' OR b.reported_at IS NULL) RETURNING b.target_id)
DELETE FROM v2_dispatch_monitor_state WHERE probe_id=$1`, probeID)
	return err
}

// Savepoint confines optional-monitor SQL errors to that subsystem. When reset
// fails, all auxiliary task/result calls fail closed until a reset succeeds.
func (s *DBService) resetDispatchProbeSafely(ctx context.Context, tx *sql.Tx, id int64) error {
	ready := false
	if s.dispatchEnsureMu.TryLock() {
		ready = s.dispatchSchemaOK
		s.dispatchEnsureMu.Unlock()
	}
	if !ready {
		s.dispatchHealthMu.Lock()
		if s.dispatchResetBlocked == nil {
			s.dispatchResetBlocked = map[int64]bool{}
		}
		s.dispatchResetBlocked[id] = true
		s.dispatchHealthMu.Unlock()
		return nil
	}
	s.dispatchHealthMu.Lock()
	if s.dispatchResetBlocked == nil {
		s.dispatchResetBlocked = map[int64]bool{}
	}
	s.dispatchResetBlocked[id] = true
	s.dispatchHealthMu.Unlock()
	if _, err := tx.ExecContext(ctx, "SAVEPOINT dispatch_reset"); err != nil {
		return err
	}
	var previousLock, previousStatement string
	if err := tx.QueryRowContext(ctx, `SELECT current_setting('lock_timeout'),current_setting('statement_timeout')`).Scan(&previousLock, &previousStatement); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `SET LOCAL lock_timeout='100ms'; SET LOCAL statement_timeout='500ms'`); err != nil {
		return err
	}
	if err := resetDispatchProbeState(ctx, tx, id); err != nil {
		if _, rollbackErr := tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT dispatch_reset"); rollbackErr != nil {
			return rollbackErr
		}
		s.dispatchHealthMu.Lock()
		if s.dispatchResetBlocked == nil {
			s.dispatchResetBlocked = map[int64]bool{}
		}
		s.dispatchResetBlocked[id] = true
		s.dispatchHealthMu.Unlock()
		log.Printf("auxiliary probe %d reset deferred: %v", id, err)
	} else {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('lock_timeout',$1,true),set_config('statement_timeout',$2,true)`, previousLock, previousStatement); err != nil {
			return err
		}
		// Keep the auxiliary session blocked until its own reset transaction
		// commits. The surrounding legacy transaction may still fail later.
	}
	_, err := tx.ExecContext(ctx, "RELEASE SAVEPOINT dispatch_reset")
	return err
}
func (s *DBService) checkDispatchProbeReset(ctx context.Context, id int64) error {
	s.dispatchHealthMu.Lock()
	blocked := s.dispatchResetBlocked[id]
	s.dispatchHealthMu.Unlock()
	if !blocked {
		return nil
	}
	if err := s.ensureDispatchMonitorSchema(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var enabled int64
	if err = tx.QueryRowContext(ctx, `SELECT enabled FROM v2_dns_probe WHERE id=$1 FOR UPDATE`, id).Scan(&enabled); err != nil {
		return err
	}
	if err = resetDispatchProbeState(ctx, tx, id); err != nil {
		return err
	}
	s.dispatchHealthMu.Lock()
	delete(s.dispatchResetBlocked, id)
	s.dispatchHealthMu.Unlock()
	if err = tx.Commit(); err != nil {
		s.dispatchHealthMu.Lock()
		if s.dispatchResetBlocked == nil {
			s.dispatchResetBlocked = map[int64]bool{}
		}
		s.dispatchResetBlocked[id] = true
		s.dispatchHealthMu.Unlock()
		return err
	}
	return nil
}

func (s *DBService) dispatchProbeResetBlocked(id int64) bool {
	s.dispatchHealthMu.Lock()
	defer s.dispatchHealthMu.Unlock()
	return s.dispatchResetBlocked[id]
}

func (s *DBService) InitializeDispatchMonitorSchema(ctx context.Context) error {
	if err := s.ensureNodeAddressSchema(ctx); err != nil {
		return err
	}
	return s.ensureDispatchMonitorSchema(ctx)
}

func (s *DBService) dispatchTaskHosts(ctx context.Context) (map[string]bool, error) {
	s.dispatchCacheMu.Lock()
	defer s.dispatchCacheMu.Unlock()
	if s.dispatchCachedHosts != nil && time.Since(s.dispatchCacheAt) < 5*time.Second {
		return s.dispatchCachedHosts, nil
	}
	entries, err := s.dispatchEntries(ctx)
	if err != nil {
		return nil, err
	}
	hosts := map[string]bool{}
	scopes := map[string]usersvc.DispatchEntry{}
	for _, entry := range entries {
		hosts[entry.Host] = true
		scopes[entry.Host] = entry
	}
	s.dispatchCachedHosts = hosts
	s.dispatchCachedScopes = scopes
	s.dispatchCacheAt = time.Now()
	return hosts, nil
}
