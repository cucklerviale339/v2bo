package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	usersvc "forest/go-api/internal/user"
	"github.com/jackc/pgx/v5/pgconn"
)

// Auxiliary targets have a separate negative namespace. They never reach the
// DNS evaluator or overwrite continuous entry-monitor state.
const dispatchCheckOffset int64 = 1 << 60
const dispatchHistoryDays int64 = 7

var dispatchCheckSchema = []string{
	`CREATE TABLE IF NOT EXISTS v2_dispatch_check_run (
 id BIGSERIAL PRIMARY KEY, status TEXT NOT NULL CHECK(status IN ('running','completed','timeout')),
 created_at BIGINT NOT NULL, deadline_at BIGINT NOT NULL, completed_at BIGINT)`,
	`CREATE TABLE IF NOT EXISTS v2_dispatch_check_target (
 id BIGSERIAL PRIMARY KEY CHECK(id < 1152921504606846976),
 kind TEXT NOT NULL CHECK(kind IN ('pool','run')), run_id BIGINT REFERENCES v2_dispatch_check_run(id) ON DELETE CASCADE,
 host VARCHAR(253) NOT NULL, port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
 name VARCHAR(255) NOT NULL DEFAULT '', enabled BOOLEAN NOT NULL DEFAULT TRUE,
 check_interval_sec INTEGER NOT NULL CHECK(check_interval_sec BETWEEN 5 AND 3600),
 tcp_timeout_ms INTEGER NOT NULL CHECK(tcp_timeout_ms BETWEEN 1 AND 60000),
 version BIGINT NOT NULL DEFAULT 1, sort INTEGER NOT NULL DEFAULT 0 CHECK(sort>=0),
 scope JSONB NOT NULL DEFAULT '{}', created_at BIGINT NOT NULL,
 CHECK((kind='pool' AND run_id IS NULL) OR (kind='run' AND run_id IS NOT NULL)))`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_dispatch_pool_address ON v2_dispatch_check_target(host,port) WHERE kind='pool'`,
	`ALTER TABLE v2_dispatch_check_target ADD COLUMN IF NOT EXISTS global_compatible BOOLEAN NOT NULL DEFAULT FALSE`,
	`CREATE INDEX IF NOT EXISTS idx_dispatch_check_run_target ON v2_dispatch_check_target(run_id,id)`,
	`CREATE INDEX IF NOT EXISTS idx_dispatch_check_run_created ON v2_dispatch_check_run(created_at DESC,id DESC)`,
	// Probe identity is a snapshot: deleting a probe must not erase history.
	`CREATE TABLE IF NOT EXISTS v2_dispatch_check_binding (
 target_id BIGINT NOT NULL REFERENCES v2_dispatch_check_target(id) ON DELETE CASCADE,
 probe_id BIGINT NOT NULL, probe_name TEXT NOT NULL, session BIGINT NOT NULL DEFAULT 1,
 sequence BIGINT NOT NULL DEFAULT 0, success BOOLEAN, latency_ms INTEGER,
 error TEXT NOT NULL DEFAULT '', resolved_ip TEXT NOT NULL DEFAULT '',
 streak INTEGER NOT NULL DEFAULT 0, reported_at BIGINT,
 PRIMARY KEY(target_id,probe_id))`,
	`CREATE INDEX IF NOT EXISTS idx_dispatch_check_binding_probe ON v2_dispatch_check_binding(probe_id,target_id)`,
}

type DispatchPoolSave struct {
	ID               int64  `json:"id"`
	Name             string `json:"name"`
	IP               string `json:"ip"`
	Port             int64  `json:"port"`
	Enabled          bool   `json:"enabled"`
	CheckIntervalSec int64  `json:"check_interval_sec"`
	TCPTimeoutMS     int64  `json:"tcp_timeout_ms"`
	Sort             int64  `json:"sort"`
	GlobalCompatible bool   `json:"global_compatible"`
}
type DispatchCheckState struct {
	DispatchMonitorState
	ConsecutiveSuccess int64 `json:"consecutive_success"`
}
type DispatchPoolItem struct {
	DispatchPoolSave
	Status     string                `json:"status"`
	Available  bool                  `json:"available"`
	Used       bool                  `json:"used"`
	References []string              `json:"references"`
	Ownership  usersvc.DispatchEntry `json:"ownership"`
	States     []DispatchCheckState  `json:"states"`
}
type DispatchRunRequest struct {
	Hosts   []string `json:"hosts"`
	PoolIDs []int64  `json:"pool_ids"`
}
type DispatchCheckRun struct {
	ID          int64  `json:"id"`
	Status      string `json:"status"`
	CreatedAt   int64  `json:"created_at"`
	DeadlineAt  int64  `json:"deadline_at"`
	CompletedAt *int64 `json:"completed_at"`
	Expected    int64  `json:"expected"`
	Received    int64  `json:"received"`
	Failed      int64  `json:"failed"`
}
type DispatchCheckResult struct {
	TargetID  int64                 `json:"target_id"`
	Name      string                `json:"name"`
	Port      int64                 `json:"port"`
	Ownership usersvc.DispatchEntry `json:"ownership"`
	DispatchCheckState
}

func normalizeDispatchPool(req *DispatchPoolSave) error {
	ip, err := netip.ParseAddr(strings.TrimSpace(req.IP))
	if err != nil || ip.Zone() != "" {
		return fmt.Errorf("%w: 请输入 IPv4 或 IPv6 地址", ErrDNSProbeInvalidRequest)
	}
	req.IP = ip.Unmap().String()
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		req.Name = req.IP
	}
	if len(req.Name) > 255 || req.ID < 0 || req.Port < 1 || req.Port > 65535 || req.CheckIntervalSec < 5 || req.CheckIntervalSec > 3600 || req.TCPTimeoutMS < 100 || req.TCPTimeoutMS > 60000 || req.Sort < 0 || req.Sort > 2147483647 {
		return fmt.Errorf("%w: 请检查名称、port、间隔、超时和排序", ErrDNSProbeInvalidRequest)
	}
	return nil
}

// Config references deliberately include disabled rules, but extras are excluded.
// Actual ownership comes from the existing three-layer configured-ID catalog.
func (s *DBService) dispatchPoolUsage(ctx context.Context) (map[string][]string, map[string]usersvc.DispatchEntry, error) {
	entries, err := s.dispatchEntries(ctx)
	if err != nil {
		return nil, nil, err
	}
	owners := map[string]usersvc.DispatchEntry{}
	for _, e := range entries {
		owners[e.Host] = e
	}
	refs, err := dispatchPoolReferences(ctx, s.db)
	return refs, owners, err
}

type dispatchQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func dispatchPoolReferences(ctx context.Context, q dispatchQueryer) (map[string][]string, error) {
	refs := map[string][]string{}
	queries := []string{
		`SELECT host,'谁是卧底 #'||id FROM v2_dispatch_investigation_group WHERE active AND host<>''`,
		`SELECT host,'内鬼管理规则 #'||id FROM v2_insider_rule WHERE host<>''`,
		`SELECT host,'节点地址规则 #'||id FROM v2_node_address_rule WHERE host<>''`,
	}
	for _, kind := range []string{"shadowsocks", "vmess", "trojan", "tuic", "hysteria", "vless", "anytls", "v2node"} {
		queries = append(queries, `SELECT host,'节点管理 `+kind+` #'||id FROM v2_server_`+kind+` WHERE host<>''`)
	}
	for _, query := range queries {
		rows, err := q.QueryContext(ctx, query)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var host, source string
			if err = rows.Scan(&host, &source); err != nil {
				rows.Close()
				return nil, err
			}
			seen := map[string]bool{}
			for _, part := range strings.Split(host, ",") {
				part = strings.TrimSpace(strings.SplitN(part, "(", 2)[0])
				ip, err := netip.ParseAddr(strings.Trim(part, "[]"))
				if err == nil && ip.Zone() == "" {
					key := ip.Unmap().String()
					if !seen[key] {
						refs[key] = append(refs[key], source)
						seen[key] = true
					}
				}
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return refs, nil
}

func (s *DBService) syncDispatchPoolBindings(ctx context.Context, probeIDs ...int64) error {
	pid := int64(0)
	if len(probeIDs) > 0 {
		pid = probeIDs[0]
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO v2_dispatch_check_binding(target_id,probe_id,probe_name)
 SELECT t.id,p.id,p.name FROM v2_dispatch_check_target t CROSS JOIN v2_dns_probe p
 WHERE t.kind='pool' AND t.enabled AND p.enabled=1 AND ($1::bigint=0 OR p.id=$1)
 ON CONFLICT(target_id,probe_id) DO UPDATE SET probe_name=EXCLUDED.probe_name
 WHERE v2_dispatch_check_binding.probe_name IS DISTINCT FROM EXCLUDED.probe_name`, pid)
	return err
}

func (s *DBService) ListDispatchPool(ctx context.Context) ([]DispatchPoolItem, error) {
	if err := s.ensureDispatchMonitorSchema(ctx); err != nil {
		return nil, err
	}
	if err := s.syncDispatchPoolBindings(ctx); err != nil {
		return nil, err
	}
	refs, owners, err := s.dispatchPoolUsage(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,host,port,enabled,check_interval_sec,tcp_timeout_ms,sort,global_compatible FROM v2_dispatch_check_target WHERE kind='pool' ORDER BY sort,id`)
	if err != nil {
		return nil, err
	}
	items := []DispatchPoolItem{}
	byID := map[int64]int{}
	for rows.Next() {
		var x DispatchPoolItem
		if err = rows.Scan(&x.ID, &x.Name, &x.IP, &x.Port, &x.Enabled, &x.CheckIntervalSec, &x.TCPTimeoutMS, &x.Sort, &x.GlobalCompatible); err != nil {
			rows.Close()
			return nil, err
		}
		x.References = append([]string{}, refs[x.IP]...)
		x.Used = len(x.References) > 0
		x.Ownership = owners[x.IP]
		x.Ownership.Host = x.IP
		x.States = []DispatchCheckState{}
		byID[x.ID] = len(items)
		items = append(items, x)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT b.target_id,b.probe_id,p.name,p.last_heartbeat_at,b.success,b.latency_ms,b.error,b.resolved_ip,b.streak,b.reported_at
 FROM v2_dispatch_check_binding b JOIN v2_dispatch_check_target t ON t.id=b.target_id
 JOIN v2_dns_probe p ON p.id=b.probe_id AND p.enabled=1 WHERE t.kind='pool' ORDER BY b.target_id,b.probe_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now().Unix()
	for rows.Next() {
		var id int64
		var x DispatchCheckState
		var heartbeat, latency, reported sql.NullInt64
		var success sql.NullBool
		if err = rows.Scan(&id, &x.ProbeID, &x.ProbeName, &heartbeat, &success, &latency, &x.Error, &x.ResolvedIP, &x.ConsecutiveSuccess, &reported); err != nil {
			return nil, err
		}
		i, ok := byID[id]
		if !ok {
			continue
		}
		m := &items[i]
		x.Online = dnsProbeHeartbeatFresh(heartbeat, now, defaultProbeOfflineSec)
		x.Stale = s.dispatchProbeResetBlocked(x.ProbeID) || !m.Enabled || !x.Online || !dispatchPoolStateFresh(reported, now, m.CheckIntervalSec, m.TCPTimeoutMS)
		if reported.Valid {
			v := reported.Int64
			x.ReportedAt = &v
		}
		if !x.Stale && success.Valid {
			v := success.Bool
			x.Success = &v
		}
		if !x.Stale && latency.Valid {
			v := latency.Int64
			x.LatencyMS = &v
		}
		m.States = append(m.States, x)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	for i := range items {
		items[i].Status, items[i].Available = classifyDispatchPool(items[i])
	}
	return items, nil
}

func classifyDispatchPool(x DispatchPoolItem) (string, bool) {
	if !x.Enabled {
		return "disabled", false
	}
	if x.Used {
		return "in_use", false
	}
	if len(x.States) == 0 {
		return "no_probe", false
	}
	online, healthy := 0, 0
	for _, st := range x.States {
		if !st.Online {
			continue
		}
		online++
		if !st.Stale && st.Success != nil {
			if !*st.Success {
				return "unhealthy", false
			}
			if st.ConsecutiveSuccess >= 2 {
				healthy++
			}
		}
	}
	if online == 0 {
		return "probe_offline", false
	}
	if healthy == online {
		return "available", true
	}
	return "checking", false
}

func dispatchPoolStateFresh(reported sql.NullInt64, now, interval, timeout int64) bool {
	return dnsFailoverProbeStateFresh(reported, now, interval, timeout, max(defaultProbeOfflineSec, 2*(interval+(timeout+999)/1000)))
}

// An atomic batch: a duplicate or invalid row rolls the whole request back.
func (s *DBService) SaveDispatchPool(ctx context.Context, items []DispatchPoolSave) ([]int64, error) {
	if len(items) == 0 || len(items) > 500 {
		return nil, fmt.Errorf("%w: 每次可保存 1 至 500 条", ErrDNSProbeInvalidRequest)
	}
	for i := range items {
		if err := normalizeDispatchPool(&items[i]); err != nil {
			return nil, err
		}
	}
	if err := s.ensureDispatchMonitorSchema(ctx); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(7642309023)`); err != nil {
		return nil, err
	}
	ids := []int64{}
	for _, x := range items {
		var id int64
		if x.ID == 0 {
			err = tx.QueryRowContext(ctx, `INSERT INTO v2_dispatch_check_target(kind,host,port,name,enabled,check_interval_sec,tcp_timeout_ms,sort,created_at,global_compatible)
   VALUES('pool',$1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`, x.IP, x.Port, x.Name, x.Enabled, x.CheckIntervalSec, x.TCPTimeoutMS, x.Sort, time.Now().Unix(), x.GlobalCompatible).Scan(&id)
		} else {
			err = tx.QueryRowContext(ctx, `UPDATE v2_dispatch_check_target SET name=$2,enabled=$3,check_interval_sec=$4,tcp_timeout_ms=$5,sort=$6,port=$8,version=version+1,global_compatible=$9
   WHERE id=$1 AND kind='pool' AND host=$7 RETURNING id`, x.ID, x.Name, x.Enabled, x.CheckIntervalSec, x.TCPTimeoutMS, x.Sort, x.IP, x.Port, x.GlobalCompatible).Scan(&id)
			if err == nil {
				_, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_check_binding SET session=session+1,sequence=0,success=NULL,latency_ms=NULL,error='',resolved_ip='',streak=0,reported_at=NULL WHERE target_id=$1`, id)
			}
		}
		if err != nil {
			var pgerr *pgconn.PgError
			if errors.As(err, &pgerr) && pgerr.Code == "23505" {
				return nil, fmt.Errorf("%w: 相同 IP 和 port 已存在", ErrDNSProbeInvalidRequest)
			}
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fmt.Errorf("%w: IP 创建后不可更改，请新增资源", ErrDNSProbeInvalidRequest)
			}
			return nil, err
		}
		ids = append(ids, id)
	}
	anyEnabled := false
	for _, item := range items {
		anyEnabled = anyEnabled || item.Enabled
	}
	if anyEnabled {
		if err = checkDispatchCapacity(ctx, tx); err != nil {
			return nil, err
		}
	}
	return ids, tx.Commit()
}

func (s *DBService) RefreshDispatchPool(ctx context.Context, ids []int64) error {
	if len(ids) == 0 || len(ids) > 500 {
		return ErrDNSProbeInvalidRequest
	}
	if err := s.ensureDispatchMonitorSchema(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		var found int64
		err = tx.QueryRowContext(ctx, `UPDATE v2_dispatch_check_target SET version=version+1 WHERE id=$1 AND kind='pool' AND enabled RETURNING id`, id).Scan(&found)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: 资源不存在或未启用", ErrDNSProbeInvalidRequest)
		}
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_check_binding SET session=session+1,sequence=0,success=NULL,latency_ms=NULL,error='',resolved_ip='',streak=0,reported_at=NULL WHERE target_id=$1`, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type DispatchPoolDeleteResult struct {
	Deleted int64 `json:"deleted"`
	Skipped int64 `json:"skipped"`
}

func (s *DBService) DeleteDispatchPool(ctx context.Context, ids []int64) (int64, error) {
	result, err := s.deleteDispatchPool(ctx, ids, false)
	return result.Deleted, err
}
func (s *DBService) DeleteFaultyDispatchPool(ctx context.Context, ids []int64) (DispatchPoolDeleteResult, error) {
	return s.deleteDispatchPool(ctx, ids, true)
}
func (s *DBService) deleteDispatchPool(ctx context.Context, ids []int64, onlyFaulty bool) (DispatchPoolDeleteResult, error) {
	out := DispatchPoolDeleteResult{}
	if len(ids) == 0 || len(ids) > 500 {
		return out, ErrDNSProbeInvalidRequest
	}
	if err := s.ensureDispatchMonitorSchema(ctx); err != nil {
		return out, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	// Bound locks to this short delete transaction. SHARE prevents concurrent
	// address-rule inserts/updates until reference checking and deletion finish.
	if _, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout='2s'`); err != nil {
		return out, err
	}
	tables := []string{"v2_insider_rule", "v2_node_address_rule"}
	for _, kind := range []string{"shadowsocks", "vmess", "trojan", "tuic", "hysteria", "vless", "anytls", "v2node"} {
		tables = append(tables, "v2_server_"+kind)
	}
	if _, err = tx.ExecContext(ctx, "LOCK TABLE "+strings.Join(tables, ",")+" IN SHARE MODE"); err != nil {
		return out, err
	}
	refs, err := dispatchPoolReferences(ctx, tx)
	if err != nil {
		return out, err
	}
	// Lock only auxiliary targets/bindings. Reporters take a target SHARE lock
	// before writing a result; never lock probe rows here and delay DNS traffic.
	seen := map[int64]bool{}
	ids = append([]int64(nil), ids...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		if id <= 0 {
			return out, ErrDNSProbeInvalidRequest
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		var x DispatchPoolItem
		err = tx.QueryRowContext(ctx, `SELECT host,enabled,check_interval_sec,tcp_timeout_ms FROM v2_dispatch_check_target WHERE kind='pool' AND id=$1 FOR UPDATE`, id).Scan(&x.IP, &x.Enabled, &x.CheckIntervalSec, &x.TCPTimeoutMS)
		if errors.Is(err, sql.ErrNoRows) {
			out.Skipped++
			continue
		}
		if err != nil {
			return out, err
		}
		if len(refs[x.IP]) > 0 {
			if onlyFaulty {
				out.Skipped++
				continue
			}
			return out, fmt.Errorf("%w: %s 有地址配置引用，请先移除引用", ErrDNSProbeInvalidRequest, x.IP)
		}
		if onlyFaulty {
			rows, e := tx.QueryContext(ctx, `SELECT p.id,p.last_heartbeat_at,b.success,b.reported_at FROM v2_dns_probe p JOIN v2_dispatch_check_binding b ON b.probe_id=p.id WHERE b.target_id=$1 AND p.enabled=1 FOR SHARE OF b`, id)
			if e != nil {
				return out, e
			}
			now := time.Now().Unix()
			for rows.Next() {
				var st DispatchCheckState
				var hb, at sql.NullInt64
				var success sql.NullBool
				if e = rows.Scan(&st.ProbeID, &hb, &success, &at); e != nil {
					rows.Close()
					return out, e
				}
				st.Online = dnsProbeHeartbeatFresh(hb, now, defaultProbeOfflineSec)
				st.Stale = s.dispatchProbeResetBlocked(st.ProbeID) || !dispatchPoolStateFresh(at, now, x.CheckIntervalSec, x.TCPTimeoutMS)
				if success.Valid {
					v := success.Bool
					st.Success = &v
				}
				x.States = append(x.States, st)
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return out, e
			}
			status, _ := classifyDispatchPool(x)
			if status != "unhealthy" {
				out.Skipped++
				continue
			}
		}
		result, e := tx.ExecContext(ctx, `DELETE FROM v2_dispatch_check_target WHERE id=$1`, id)
		if e != nil {
			return out, e
		}
		n, e := result.RowsAffected()
		if e != nil {
			return out, e
		}
		out.Deleted += n
	}
	if err = tx.Commit(); err != nil {
		return DispatchPoolDeleteResult{}, err
	}
	return out, nil
}

// Shared by pool and entry configuration writes, so concurrent requests cannot
// overbook an individual probe's auxiliary task budget.
func checkDispatchCapacity(ctx context.Context, tx *sql.Tx) error {
	var total int64
	err := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM v2_dispatch_check_target WHERE kind='pool' AND enabled)+COALESCE((SELECT max(n) FROM (SELECT count(*) n FROM v2_dispatch_monitor m JOIN v2_dispatch_monitor_probe b ON b.monitor_id=m.id WHERE m.enabled GROUP BY b.probe_id) counts),0)`).Scan(&total)
	if err != nil {
		return err
	}
	if total > 1000 {
		return fmt.Errorf("%w: 每枚探针最多支持 1000 个新增监控目标（入口与备用池合计），请先停用部分监控", ErrDNSProbeInvalidRequest)
	}
	return nil
}

func (s *DBService) expireDispatchRuns(ctx context.Context) error {
	now := time.Now().Unix()
	_, err := s.db.ExecContext(ctx, `WITH expired AS (
 UPDATE v2_dispatch_check_run SET status='timeout',completed_at=$1 WHERE status='running' AND deadline_at<=$1 RETURNING id),
 doomed AS (SELECT id FROM v2_dispatch_check_run WHERE status<>'running' AND created_at<$2 ORDER BY id LIMIT 100)
 DELETE FROM v2_dispatch_check_run WHERE id IN(SELECT id FROM doomed)`, now, now-dispatchHistoryDays*86400)
	return err
}

func (s *DBService) StartDispatchRun(ctx context.Context, req DispatchRunRequest) (int64, error) {
	if len(req.Hosts)+len(req.PoolIDs) == 0 || len(req.Hosts)+len(req.PoolIDs) > 500 {
		return 0, fmt.Errorf("%w: 请选择 1 至 500 个目标", ErrDNSProbeInvalidRequest)
	}
	monitors, err := s.ListDispatchMonitors(ctx)
	if err != nil {
		return 0, err
	}
	pools, err := s.ListDispatchPool(ctx)
	if err != nil {
		return 0, err
	}
	type selection struct {
		host, name    string
		port, timeout int64
		scope         usersvc.DispatchEntry
		probes        []int64
	}
	selected := []selection{}
	seen := map[string]bool{}
	for _, host := range req.Hosts {
		found := false
		for _, m := range monitors {
			if m.Host == host && m.Enabled && len(m.ProbeIDs) > 0 {
				key := fmt.Sprintf("%s:%d", m.Host, m.CheckPort)
				if !seen[key] {
					selected = append(selected, selection{m.Host, m.Host, m.CheckPort, m.TCPTimeoutMS, m.DispatchEntry, m.ProbeIDs})
					seen[key] = true
				}
				found = true
				break
			}
		}
		if !found {
			return 0, fmt.Errorf("%w: 所选入口已变化或未启用监控", ErrDNSProbeInvalidRequest)
		}
	}
	for _, id := range req.PoolIDs {
		found := false
		for _, p := range pools {
			if p.ID == id && p.Enabled {
				key := fmt.Sprintf("%s:%d", p.IP, p.Port)
				if !seen[key] {
					probes := []int64{}
					for _, st := range p.States {
						probes = append(probes, st.ProbeID)
					}
					selected = append(selected, selection{p.IP, p.Name, p.Port, p.TCPTimeoutMS, p.Ownership, probes})
					seen[key] = true
				}
				found = true
				break
			}
		}
		if !found {
			return 0, fmt.Errorf("%w: 所选备用资源不存在或未启用", ErrDNSProbeInvalidRequest)
		}
	}
	if err = s.expireDispatchRuns(ctx); err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(7642309021)`); err != nil {
		return 0, err
	}
	var active int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM v2_dispatch_check_run WHERE status='running'`).Scan(&active); err != nil {
		return 0, err
	}
	if active >= 10 {
		return 0, fmt.Errorf("%w: 已有 10 轮检测运行中，请稍后重试", ErrDNSProbeInvalidRequest)
	}
	// Bound the Cartesian product before inserting tasks.
	pairs := 0
	for _, x := range selected {
		pairs += len(x.probes)
	}
	if pairs == 0 || pairs > 10000 {
		return 0, fmt.Errorf("%w: 没有启用探针或本轮结果超过 10000 份", ErrDNSProbeInvalidRequest)
	}
	var runID int64
	now := time.Now().Unix()
	if err = tx.QueryRowContext(ctx, `INSERT INTO v2_dispatch_check_run(status,created_at,deadline_at) VALUES('running',$1,$2) RETURNING id`, now, now+300).Scan(&runID); err != nil {
		return 0, err
	}
	for _, x := range selected {
		scope, _ := json.Marshal(x.scope)
		var targetID int64
		if err = tx.QueryRowContext(ctx, `INSERT INTO v2_dispatch_check_target(kind,run_id,host,port,name,check_interval_sec,tcp_timeout_ms,scope,created_at)
   VALUES('run',$1,$2,$3,$4,30,$5,$6,$7) RETURNING id`, runID, x.host, x.port, x.name, x.timeout, scope, now).Scan(&targetID); err != nil {
			return 0, err
		}
		for _, pid := range x.probes {
			var name string
			err = tx.QueryRowContext(ctx, `SELECT name FROM v2_dns_probe WHERE id=$1 AND enabled=1 FOR SHARE`, pid).Scan(&name)
			if errors.Is(err, sql.ErrNoRows) {
				return 0, fmt.Errorf("%w: 探针已变化，请刷新重试", ErrDNSProbeInvalidRequest)
			}
			if err != nil {
				return 0, err
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO v2_dispatch_check_binding(target_id,probe_id,probe_name) VALUES($1,$2,$3)`, targetID, pid, name); err != nil {
				return 0, err
			}
		}
	}
	return runID, tx.Commit()
}

func (s *DBService) ListDispatchRuns(ctx context.Context, page int) ([]DispatchCheckRun, int64, error) {
	if page < 1 || page > 100000 {
		return nil, 0, ErrDNSProbeInvalidRequest
	}
	if err := s.ensureDispatchMonitorSchema(ctx); err != nil {
		return nil, 0, err
	}
	if err := s.expireDispatchRuns(ctx); err != nil {
		return nil, 0, err
	}
	cutoff := time.Now().Unix() - dispatchHistoryDays*86400
	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM v2_dispatch_check_run WHERE created_at>=$1 OR status='running'`, cutoff).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT r.id,r.status,r.created_at,r.deadline_at,r.completed_at,count(b.probe_id),count(b.reported_at),count(*) FILTER(WHERE b.success=FALSE)
 FROM (SELECT * FROM v2_dispatch_check_run WHERE created_at>=$1 OR status='running' ORDER BY id DESC LIMIT 20 OFFSET $2) r
 LEFT JOIN v2_dispatch_check_target t ON t.run_id=r.id LEFT JOIN v2_dispatch_check_binding b ON b.target_id=t.id
 GROUP BY r.id,r.status,r.created_at,r.deadline_at,r.completed_at ORDER BY r.id DESC`, cutoff, (page-1)*20)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	runs := []DispatchCheckRun{}
	for rows.Next() {
		var x DispatchCheckRun
		var complete sql.NullInt64
		if err = rows.Scan(&x.ID, &x.Status, &x.CreatedAt, &x.DeadlineAt, &complete, &x.Expected, &x.Received, &x.Failed); err != nil {
			return nil, 0, err
		}
		if complete.Valid {
			x.CompletedAt = &complete.Int64
		}
		runs = append(runs, x)
	}
	return runs, total, rows.Err()
}

func (s *DBService) DispatchRunResults(ctx context.Context, id int64, page int) ([]DispatchCheckResult, int64, error) {
	if id <= 0 || page < 1 || page > 100000 {
		return nil, 0, ErrDNSProbeInvalidRequest
	}
	if err := s.ensureDispatchMonitorSchema(ctx); err != nil {
		return nil, 0, err
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM v2_dispatch_check_binding b JOIN v2_dispatch_check_target t ON t.id=b.target_id WHERE t.run_id=$1`, id).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT t.id,t.name,t.port,t.scope,b.probe_id,b.probe_name,b.success,b.latency_ms,b.error,b.resolved_ip,b.reported_at
 FROM v2_dispatch_check_target t JOIN v2_dispatch_check_binding b ON b.target_id=t.id WHERE t.run_id=$1
 ORDER BY b.success ASC NULLS FIRST,t.id,b.probe_id LIMIT 100 OFFSET $2`, id, (page-1)*100)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	results := []DispatchCheckResult{}
	for rows.Next() {
		var x DispatchCheckResult
		var scope []byte
		var success sql.NullBool
		var latency, reported sql.NullInt64
		if err = rows.Scan(&x.TargetID, &x.Name, &x.Port, &scope, &x.ProbeID, &x.ProbeName, &success, &latency, &x.Error, &x.ResolvedIP, &reported); err != nil {
			return nil, 0, err
		}
		if err = json.Unmarshal(scope, &x.Ownership); err != nil {
			return nil, 0, err
		}
		if success.Valid {
			x.Success = &success.Bool
		}
		if latency.Valid {
			x.LatencyMS = &latency.Int64
		}
		if reported.Valid {
			x.ReportedAt = &reported.Int64
		}
		results = append(results, x)
	}
	return results, total, rows.Err()
}

func (s *DBService) ClearDispatchRuns(ctx context.Context) (int64, error) {
	if err := s.ensureDispatchMonitorSchema(ctx); err != nil {
		return 0, err
	}
	if err := s.expireDispatchRuns(ctx); err != nil {
		return 0, err
	}
	r, err := s.db.ExecContext(ctx, `DELETE FROM v2_dispatch_check_run WHERE status<>'running'`)
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}

func (s *DBService) ListDispatchCheckTasks(ctx context.Context, pid int64) ([]DNSProbeTask, error) {
	if err := s.checkDispatchProbeReset(ctx, pid); err != nil {
		return nil, err
	}
	if err := s.ensureDispatchMonitorSchema(ctx); err != nil {
		return nil, err
	}
	if err := s.expireDispatchRuns(ctx); err != nil {
		return nil, err
	}
	if err := s.syncDispatchPoolBindings(ctx, pid); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT t.id,t.host,t.port,t.tcp_timeout_ms,t.check_interval_sec,t.version,b.session
 FROM v2_dispatch_check_target t JOIN v2_dispatch_check_binding b ON b.target_id=t.id
 JOIN v2_dns_probe p ON p.id=b.probe_id AND p.enabled=1 LEFT JOIN v2_dispatch_check_run r ON r.id=t.run_id
 WHERE b.probe_id=$1 AND t.enabled AND (t.kind='pool' OR (r.status='running' AND b.reported_at IS NULL)) ORDER BY t.id`, pid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tasks := []DNSProbeTask{}
	for rows.Next() {
		var x DNSProbeTask
		var id int64
		if err = rows.Scan(&id, &x.CheckHost, &x.CheckPort, &x.TCPTimeoutMS, &x.CheckIntervalSec, &x.TargetVersion, &x.RunID); err != nil {
			return nil, err
		}
		x.TargetID = -(dispatchCheckOffset + id)
		tasks = append(tasks, x)
	}
	return tasks, rows.Err()
}

func (s *DBService) ReportDispatchCheckResults(ctx context.Context, pid int64, req DNSProbeResultsRequest) (DNSProbeReportResult, error) {
	summary := DNSProbeReportResult{GroupIDs: []int64{}}
	if pid <= 0 || len(req.Results) > 500 {
		return summary, ErrDNSProbeInvalidRequest
	}
	validated := DNSProbeResultsRequest{Results: append([]DNSProbeResult{}, req.Results...)}
	for i, r := range validated.Results {
		if r.TargetID >= -dispatchCheckOffset || r.TargetID <= -2*dispatchCheckOffset || r.TargetVersion <= 0 || r.RunID <= 0 {
			return summary, ErrDNSProbeInvalidRequest
		}
		validated.Results[i].TargetID = -r.TargetID - dispatchCheckOffset
		if _, err := dispatchResultSequence(r); err != nil {
			return summary, err
		}
	}
	if err := normalizeDNSProbeResultsRequest(&validated); err != nil {
		return summary, err
	}
	// Run targets are created monotonically; consistent order prevents two
	// multi-run batches from acquiring historical-run locks in reverse order.
	sort.SliceStable(validated.Results, func(i, j int) bool { return validated.Results[i].TargetID < validated.Results[j].TargetID })
	if err := s.ensureDispatchMonitorSchema(ctx); err != nil {
		return summary, err
	}
	if err := s.checkDispatchProbeReset(ctx, pid); err != nil {
		return summary, err
	}
	history := s.prepareDispatchHistory(ctx)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return summary, err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	var enabled int64
	var heartbeat sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT enabled,last_heartbeat_at FROM v2_dns_probe WHERE id=$1 FOR UPDATE`, pid).Scan(&enabled, &heartbeat)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && enabled != 1) {
		return summary, ErrDNSProbeUnauthorized
	}
	if err != nil {
		return summary, err
	}
	if !dnsProbeHeartbeatFresh(heartbeat, now, defaultProbeOfflineSec) {
		return summary, ErrDNSProbeHeartbeatRequired
	}
	if s.dispatchProbeResetBlocked(pid) {
		return summary, ErrDNSProbeHeartbeatRequired
	}
	for _, r := range validated.Results {
		var kind string
		var version, interval, timeout int64
		var run sql.NullInt64
		// Lock a historical run before its target, matching cascade deletion.
		err = tx.QueryRowContext(ctx, `SELECT kind,version,check_interval_sec,tcp_timeout_ms,run_id FROM v2_dispatch_check_target WHERE id=$1 AND enabled`, r.TargetID).Scan(&kind, &version, &interval, &timeout, &run)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && version != r.TargetVersion) {
			summary.Skipped++
			continue
		}
		if err != nil {
			return summary, err
		}
		if kind == "run" {
			var status string
			var deadline int64
			err = tx.QueryRowContext(ctx, `SELECT status,deadline_at FROM v2_dispatch_check_run WHERE id=$1 FOR UPDATE`, run.Int64).Scan(&status, &deadline)
			if errors.Is(err, sql.ErrNoRows) {
				summary.Skipped++
				continue
			}
			if err != nil {
				return summary, err
			}
			if status != "running" || now >= deadline {
				summary.Skipped++
				continue
			}
		}
		err = tx.QueryRowContext(ctx, `SELECT version FROM v2_dispatch_check_target WHERE id=$1 AND enabled FOR SHARE`, r.TargetID).Scan(&version)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && version != r.TargetVersion) {
			summary.Skipped++
			continue
		}
		if err != nil {
			return summary, err
		}
		var session, previousSeq, streak int64
		var previousAt sql.NullInt64
		err = tx.QueryRowContext(ctx, `SELECT session,sequence,streak,reported_at FROM v2_dispatch_check_binding WHERE target_id=$1 AND probe_id=$2 FOR UPDATE`, r.TargetID, pid).Scan(&session, &previousSeq, &streak, &previousAt)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && session != r.RunID) {
			summary.Skipped++
			continue
		}
		if err != nil {
			return summary, err
		}
		seq, _ := dispatchResultSequence(r)
		if seq <= previousSeq || (kind == "run" && previousAt.Valid) {
			summary.Duplicates++
			continue
		}
		if !dispatchPoolStateFresh(previousAt, now, interval, timeout) {
			streak = 0
		}
		if *r.Success {
			streak = min(streak+1, 2147483647)
		} else {
			streak = 0
		}
		values := dnsProbeStateWriteValues(r)
		_, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_check_binding SET sequence=$3,success=$4,latency_ms=$5,error=$6,resolved_ip=$7,streak=$8,reported_at=$9 WHERE target_id=$1 AND probe_id=$2`, r.TargetID, pid, seq, *r.Success, values.Latency, values.Error, r.ResolvedIP, streak, now)
		if err != nil {
			return summary, err
		}
		if kind == "run" {
			_, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_check_run r SET status='completed',completed_at=$2 WHERE id=$1 AND status='running' AND NOT EXISTS(SELECT 1 FROM v2_dispatch_check_target t JOIN v2_dispatch_check_binding b ON b.target_id=t.id WHERE t.run_id=r.id AND b.reported_at IS NULL)`, run.Int64, now)
			if err != nil {
				return summary, err
			}
		}
		summary.Accepted++
		if kind == "pool" {
			history.add("pool", pid, r, now, streak)
		}
	}
	s.persistDispatchHistory(ctx, tx, history)
	return summary, tx.Commit()
}
