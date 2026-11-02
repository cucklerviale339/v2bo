package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"

	"forest/go-api/internal/platform/addrutil"
	usersvc "forest/go-api/internal/user"
)

type InvestigationSettings struct {
	Enabled             bool   `json:"enabled"`
	Scope               string `json:"scope"`
	Revision            int64  `json:"revision"`
	ArmedAt             int64  `json:"armed_at"`
	EntryWindowMinutes  int64  `json:"entry_window_minutes"`
	GlobalWindowMinutes int64  `json:"global_window_minutes"`
	GlobalMax           int64  `json:"global_max"`
}
type InvestigationGroup struct {
	ID           int64    `json:"id"`
	RootID       int64    `json:"root_id"`
	ParentID     int64    `json:"parent_id"`
	LegacyRootID int64    `json:"legacy_root_id"`
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`
	Host         string   `json:"host"`
	MonitorID    int64    `json:"monitor_id"`
	Active       bool     `json:"active"`
	ManualOnly   bool     `json:"manual_only"`
	Revision     int64    `json:"revision"`
	Generation   int64    `json:"generation"`
	EpochAt      int64    `json:"epoch_at"`
	ReadyAt      int64    `json:"ready_at"`
	ConfigKey    string   `json:"-"`
	Reason       string   `json:"reason"`
	NoPullCount  int64    `json:"no_pull_count"`
	UserIDs      []string `json:"user_ids"`
}
type InvestigationEvent struct {
	ID             int64           `json:"id"`
	RootID         int64           `json:"root_id"`
	GroupID        int64           `json:"group_id"`
	Kind           string          `json:"kind"`
	FirstFailureAt int64           `json:"first_failure_at"`
	CreatedAt      int64           `json:"created_at"`
	Payload        json.RawMessage `json:"payload"`
}
type InvestigationView struct {
	Settings    InvestigationSettings `json:"settings"`
	Groups      []InvestigationGroup  `json:"groups"`
	Events      []InvestigationEvent  `json:"events"`
	Total       int64                 `json:"total"`
	Page        int64                 `json:"page"`
	WorkerError string                `json:"worker_error,omitempty"`
}

func (s *DBService) ensureInvestigation(ctx context.Context) error {
	if err := s.ensureNodeAddressSchema(ctx); err != nil {
		return err
	}
	if err := s.ensureDispatchMonitorSchema(ctx); err != nil {
		return err
	}
	if err := s.ensureDispatchHistorySchema(ctx); err != nil {
		return err
	}
	if err := s.ensureDispatchAutoSplitSchema(ctx); err != nil {
		return err
	}
	return s.migrateInvestigationNames(ctx)
}

// Naming is local to this module; member IDs are displayed separately.
func investigationGroupName(kind string) string {
	if kind == "confirmed" {
		return "实锤内鬼"
	}
	if kind == "observation" {
		return "观察"
	}
	if kind == "recent" {
		return "120分钟"
	}
	return "卧底"
}

var investigationLegacyRangeName = regexp.MustCompile(`^(卧底|观察) [0-9]+(-[0-9]+)?(, [0-9]+(-[0-9]+)?)*$`)

func (s *DBService) migrateInvestigationNames(ctx context.Context) error {
	s.investigationNameMu.Lock()
	defer s.investigationNameMu.Unlock()
	if s.investigationNamesMigrated {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(7642309023)`); err != nil {
		return err
	}
	groups, err := readInvestigationGroups(ctx, tx, true)
	if err != nil {
		return err
	}
	for _, g := range groups {
		old := strings.TrimSuffix(g.Name, " · 无人拉取")
		if old != "候选组" && old != "观察" && !strings.HasPrefix(old, "候选组 · ") && !investigationLegacyRangeName.MatchString(old) {
			continue
		}
		name := investigationGroupName(g.Kind)
		if g.NoPullCount > 0 {
			name += " · 无人拉取"
		}
		if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET name=$2,revision=revision+1 WHERE id=$1 AND name<>$2`, g.ID, name); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.investigationNamesMigrated = true
	return nil
}
func readInvestigationSettings(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, lock bool) (InvestigationSettings, error) {
	var v InvestigationSettings
	query := `SELECT enabled,scope,revision,armed_at,entry_window_minutes,global_window_minutes,global_max FROM v2_dispatch_investigation_settings WHERE id=1`
	if lock {
		query += ` FOR UPDATE`
	}
	err := q.QueryRowContext(ctx, query).Scan(&v.Enabled, &v.Scope, &v.Revision, &v.ArmedAt, &v.EntryWindowMinutes, &v.GlobalWindowMinutes, &v.GlobalMax)
	return v, err
}
func readInvestigationGroups(ctx context.Context, q dispatchQueryer, active bool) ([]InvestigationGroup, error) {
	rows, err := q.QueryContext(ctx, `SELECT g.id,g.root_id,g.parent_id,g.legacy_root_id,g.name,g.kind,g.host,g.monitor_id,g.active,g.manual_only,g.revision,g.generation,g.epoch_at,g.ready_at,g.config_key,g.reason,g.no_pull_count,COALESCE((SELECT jsonb_agg(m.user_id::text ORDER BY m.user_id) FROM v2_dispatch_investigation_member m JOIN v2_user u ON u.id=m.user_id WHERE m.group_id=g.id),'[]'::jsonb) FROM v2_dispatch_investigation_group g WHERE NOT $1 OR g.active ORDER BY g.id`, active)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []InvestigationGroup{}
	for rows.Next() {
		var g InvestigationGroup
		var ids []byte
		if err = rows.Scan(&g.ID, &g.RootID, &g.ParentID, &g.LegacyRootID, &g.Name, &g.Kind, &g.Host, &g.MonitorID, &g.Active, &g.ManualOnly, &g.Revision, &g.Generation, &g.EpochAt, &g.ReadyAt, &g.ConfigKey, &g.Reason, &g.NoPullCount, &ids); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(ids, &g.UserIDs); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
func (s *DBService) GetInvestigation(ctx context.Context, page int64) (InvestigationView, error) {
	out := InvestigationView{Groups: []InvestigationGroup{}, Events: []InvestigationEvent{}, Page: page}
	if page < 1 || page > 100000 {
		return out, splitEditInvalid("页码无效")
	}
	if err := s.ensureInvestigation(ctx); err != nil {
		return out, err
	}
	var err error
	out.Settings, err = readInvestigationSettings(ctx, s.db, false)
	if err != nil {
		return out, err
	}
	out.Groups, err = readInvestigationGroups(ctx, s.db, true)
	if err != nil {
		return out, err
	}
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM v2_dispatch_investigation_event`).Scan(&out.Total); err != nil {
		return out, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,root_id,group_id,kind,first_failure_at,created_at,payload FROM v2_dispatch_investigation_event ORDER BY id DESC LIMIT 20 OFFSET $1`, (page-1)*20)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var e InvestigationEvent
		if err = rows.Scan(&e.ID, &e.RootID, &e.GroupID, &e.Kind, &e.FirstFailureAt, &e.CreatedAt, &e.Payload); err != nil {
			return out, err
		}
		out.Events = append(out.Events, e)
	}
	s.dispatchAutoSplitMu.Lock()
	out.WorkerError = s.investigationLastError
	s.dispatchAutoSplitMu.Unlock()
	return out, rows.Err()
}
func (s *DBService) SaveInvestigation(ctx context.Context, v InvestigationSettings) error {
	if v.Scope != "" && v.Scope != "all" && v.Scope != "multi_range" {
		return splitEditInvalid("生效范围无效")
	}
	if v.Revision < 1 || v.EntryWindowMinutes < 1 || v.EntryWindowMinutes > 10080 || v.GlobalWindowMinutes < 1 || v.GlobalWindowMinutes > 10080 || v.GlobalMax < 1 || v.GlobalMax > 100 {
		return splitEditInvalid("频率设置或版本无效")
	}
	if err := s.ensureInvestigation(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout='1s'; SET LOCAL statement_timeout='5s'`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(7642309023)`); err != nil {
		return err
	}
	current, err := readInvestigationSettings(ctx, tx, true)
	if err != nil {
		return err
	}
	if v.Revision != current.Revision {
		return splitEditInvalid("设置已更新，请刷新后重试")
	}
	if v.Scope == "" {
		v.Scope = current.Scope
	}
	now := time.Now().Unix()
	if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_settings SET enabled=$1,entry_window_minutes=$2,global_window_minutes=$3,global_max=$4,armed_at=$5,scope=$6,revision=revision+1 WHERE id=1`, v.Enabled, v.EntryWindowMinutes, v.GlobalWindowMinutes, v.GlobalMax, now, v.Scope); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET epoch_at=$1,ready_at=0,config_key='',generation=generation+1,revision=revision+1,reason=CASE WHEN manual_only THEN reason ELSE '等待入口恢复正常后重新观察' END WHERE active`, now); err != nil {
		return err
	}
	if err = investigationAudit(ctx, tx, 0, 0, "settings", 0, map[string]any{"before": current, "after": v}); err != nil {
		return err
	}
	return tx.Commit()
}
func investigationAudit(ctx context.Context, tx *sql.Tx, root, group int64, kind string, first int64, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,first_failure_at,created_at,payload) VALUES($1,$2,$3,$4,$5,$6)`, root, group, kind, first, time.Now().Unix(), string(raw))
	return err
}
func (s *DBService) invalidateDispatchCatalog() {
	s.dispatchCacheMu.Lock()
	s.dispatchCacheAt = time.Time{}
	s.dispatchCachedHosts = nil
	s.dispatchCachedScopes = nil
	s.dispatchCacheMu.Unlock()
}

func (s *DBService) cleanupInvestigationDeliveries(ctx context.Context) error {
	if err := s.ensureNodeAddressSchema(ctx); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `WITH cleared AS (DELETE FROM v2_dispatch_investigation_delivery_recent d WHERE delivered_at<$1 AND NOT EXISTS(SELECT 1 FROM v2_dispatch_investigation_group g WHERE g.id=d.group_id AND g.active AND g.generation=d.generation)) DELETE FROM v2_dispatch_investigation_delivery d WHERE delivered_at<$1 AND NOT EXISTS(SELECT 1 FROM v2_dispatch_investigation_group g WHERE g.id=d.group_id AND g.active AND g.generation=d.generation)`, time.Now().Add(-90*24*time.Hour).Unix())
	return err
}

func (s *DBService) runInvestigationCycle(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	err := s.investigationCycle(ctx)
	s.dispatchAutoSplitMu.Lock()
	s.investigationLastError = ""
	if err != nil {
		s.investigationLastError = "自动筛选暂不可用，本轮未继续执行；请检查服务日志"
	}
	s.dispatchAutoSplitMu.Unlock()
	return err
}
func (s *DBService) investigationCycle(ctx context.Context) error {
	if err := s.ensureInvestigation(ctx); err != nil {
		return err
	}
	settings, err := readInvestigationSettings(ctx, s.db, false)
	if err != nil || !settings.Enabled {
		return err
	}
	if err = s.bootstrapInvestigation(ctx); err != nil {
		return err
	}
	groups, err := readInvestigationGroups(ctx, s.db, true)
	if err != nil {
		return err
	}
	// A bounded rotating batch prevents a large inventory starving later roots.
	s.dispatchAutoSplitMu.Lock()
	cursor := s.investigationCursor
	s.dispatchAutoSplitMu.Unlock()
	index := sort.Search(len(groups), func(i int) bool { return groups[i].ID > cursor })
	groups = append(append([]InvestigationGroup{}, groups[index:]...), groups[:index]...)
	for i, g := range groups {
		if i >= 30 {
			break
		}
		s.dispatchAutoSplitMu.Lock()
		s.investigationCursor = g.ID
		s.dispatchAutoSplitMu.Unlock()
		if g.ManualOnly || len(g.UserIDs) <= 1 {
			continue
		}
		if err = s.processInvestigation(ctx, g.ID); err != nil {
			return err
		}
	}
	return nil
}

// Freeze the existing account roster without consulting availability, plans or
// permissions. The original selector remains the admission boundary forever.
func (s *DBService) bootstrapInvestigation(ctx context.Context) error {
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
	entries, err := usersvc.DispatchEntriesFrom(ctx, tx)
	if err != nil {
		return err
	}
	byHost := map[string]usersvc.DispatchEntry{}
	for _, e := range entries {
		byHost[e.Host] = e
	}
	eligibleHosts, err := investigationScopeHosts(ctx, tx, settings.Scope)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT m.id,m.host,COALESCE(g.root_group_id,0) FROM v2_dispatch_monitor m LEFT JOIN v2_dispatch_auto_split_group g ON g.monitor_id=m.id WHERE m.enabled AND NOT m.deleted AND EXISTS(SELECT 1 FROM v2_dispatch_monitor_probe b WHERE b.monitor_id=m.id) AND NOT EXISTS(SELECT 1 FROM v2_dispatch_investigation_group i WHERE i.monitor_id=m.id) ORDER BY m.id`)
	if err != nil {
		return err
	}
	type original struct {
		id     int64
		host   string
		legacy int64
	}
	originals := []original{}
	for rows.Next() {
		var o original
		if err = rows.Scan(&o.id, &o.host, &o.legacy); err != nil {
			break
		}
		originals = append(originals, o)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	for _, o := range originals {
		if settings.Scope == "multi_range" && !eligibleHosts[o.host] {
			continue
		}
		entry, ok := byHost[o.host]
		if !ok {
			continue
		}
		ids, e := usersvc.DispatchAccountIDs(ctx, tx, entry)
		if e != nil {
			return e
		}
		if len(ids) == 0 {
			continue
		}
		var overlap bool
		raw, _ := json.Marshal(ids)
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v2_dispatch_investigation_member m WHERE m.origin_host=$1 AND m.user_id IN(SELECT value::bigint FROM jsonb_array_elements_text($2::jsonb)))`, o.host, string(raw)).Scan(&overlap); err != nil {
			return err
		}
		if overlap {
			continue
		}
		var root int64
		name := investigationGroupName("candidate")
		reason := "等待入口正常后开始观察"
		if len(ids) == 1 {
			reason = "单人组，仅人工操作"
		}
		if err = tx.QueryRowContext(ctx, `INSERT INTO v2_dispatch_investigation_group(name,kind,host,monitor_id,legacy_root_id,manual_only,epoch_at,created_at,reason) VALUES($1,'candidate',$2,$3,$4,$5,$6,$6,$7) RETURNING id`, name, o.host, o.id, o.legacy, len(ids) == 1, now, reason).Scan(&root); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET root_id=id WHERE id=$1`, root); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO v2_dispatch_investigation_member(root_id,origin_host,user_id,group_id) SELECT $1,$2,value::bigint,$1 FROM jsonb_array_elements_text($3::jsonb)`, root, o.host, string(raw)); err != nil {
			return err
		}
		if err = investigationAudit(ctx, tx, root, root, "started", 0, map[string]any{"host": o.host, "user_ids": ids}); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err == nil {
		s.invalidateDispatchCatalog()
	}
	return err
}

func investigationScopeHosts(ctx context.Context, q usersvc.DispatchQueryer, scope string) (map[string]bool, error) {
	hosts := map[string]bool{}
	if scope != "multi_range" {
		return hosts, nil
	}
	entries, err := usersvc.DispatchEntriesBeforeInvestigationFrom(ctx, q)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if len(e.UserIDRanges) >= 2 {
			hosts[e.Host] = true
		}
	}
	return hosts, nil
}

func investigationGroupInScope(ctx context.Context, tx *sql.Tx, scope string, root int64) (bool, error) {
	if scope != "multi_range" {
		return true, nil
	}
	hosts, err := investigationScopeHosts(ctx, tx, scope)
	if err != nil {
		return false, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT origin_host FROM v2_dispatch_investigation_member WHERE root_id=$1`, root)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err != nil {
			return false, err
		}
		found = found || hosts[host]
	}
	return found, rows.Err()
}

type InvestigationEdit struct {
	ID         int64  `json:"id"`
	Revision   int64  `json:"revision"`
	Name       string `json:"name"`
	Host       string `json:"host"`
	ManualOnly bool   `json:"manual_only"`
}

func (s *DBService) EditInvestigation(ctx context.Context, v InvestigationEdit) error {
	v.Host = normalizeDispatchMonitorHost(v.Host)
	v.Name = strings.TrimSpace(v.Name)
	if v.ID < 1 || v.Revision < 1 || v.Name == "" || len([]rune(v.Name)) > 200 || !addrutil.IsIPOrHostname(v.Host) {
		return splitEditInvalid("分组名称或下发地址无效")
	}
	if err := s.ensureInvestigation(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout='1s'; SET LOCAL statement_timeout='5s'`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(7642309023)`); err != nil {
		return err
	}
	groups, err := readInvestigationGroups(ctx, tx, true)
	if err != nil {
		return err
	}
	var g InvestigationGroup
	for _, x := range groups {
		if x.ID == v.ID {
			g = x
		}
	}
	if g.ID == 0 || g.Revision != v.Revision {
		return splitEditInvalid("分组已变化，请刷新后重试")
	}
	if len(g.UserIDs) <= 1 && !v.ManualOnly {
		return splitEditInvalid("单人组只能人工操作")
	}
	if err = lockInvestigationAddresses(ctx, tx); err != nil {
		return err
	}
	before, err := usersvc.DispatchEntriesFrom(ctx, tx)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	monitor := g.MonitorID
	if v.Host != g.Host {
		for _, entry := range before {
			if entry.Host == v.Host {
				return splitEditInvalid("新地址已经参与其他实际下发")
			}
		}
		var exists bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v2_dispatch_monitor WHERE host=$1)`, v.Host).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return splitEditInvalid("新地址已存在监控配置，请使用独立入口")
		}
		refs, e := dispatchPoolReferences(ctx, tx)
		if e != nil {
			return e
		}
		if len(refs[v.Host]) > 0 {
			return splitEditInvalid("新地址已被其他规则引用")
		}
		monitor, err = investigationCloneMonitor(ctx, tx, g.MonitorID, v.Host)
		if err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET name=$2,host=$3,monitor_id=$4,manual_only=$5,revision=revision+1,generation=generation+1,epoch_at=$6,ready_at=0,config_key='',reason='人工编辑后重新观察' WHERE id=$1`, g.ID, v.Name, v.Host, monitor, v.ManualOnly, now); err != nil {
		return err
	}
	if err = investigationAudit(ctx, tx, g.RootID, g.ID, "edited", 0, map[string]any{"before": g, "after": v}); err != nil {
		return err
	}
	after, err := usersvc.DispatchEntriesFrom(ctx, tx)
	if err != nil {
		return err
	}
	moves := map[int64]string{}
	for _, id := range investigationGroupIDs(g) {
		moves[id] = v.Host
	}
	if err = verifyInvestigationMove(before, after, g.Host, moves); err != nil {
		return splitEditInvalid(err.Error())
	}
	if err = checkDispatchCapacity(ctx, tx); err != nil {
		return err
	}
	if err = tx.Commit(); err == nil {
		s.invalidateDispatchCatalog()
	}
	return err
}
func investigationCloneMonitor(ctx context.Context, tx *sql.Tx, source int64, host string) (int64, error) {
	var id int64
	err := tx.QueryRowContext(ctx, `INSERT INTO v2_dispatch_monitor(host,check_port,enabled,check_interval_sec,tcp_timeout_ms) SELECT $2,check_port,TRUE,check_interval_sec,tcp_timeout_ms FROM v2_dispatch_monitor WHERE id=$1 AND enabled AND NOT deleted RETURNING id`, source, host).Scan(&id)
	if err != nil {
		return 0, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO v2_dispatch_monitor_probe(monitor_id,probe_id) SELECT $2,b.probe_id FROM v2_dispatch_monitor_probe b JOIN v2_dns_probe p ON p.id=b.probe_id AND p.enabled=1 WHERE b.monitor_id=$1`, source, id)
	return id, err
}

// Used before the old splitter takes ownership, including when the new master
// switch is off: disabling automation must not undo dispatch or singleton locks.
func investigationManaged(ctx context.Context, tx *sql.Tx, entry usersvc.DispatchEntry) (bool, error) {
	var exists bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v2_dispatch_investigation_group WHERE active AND host=$1)`, entry.Host).Scan(&exists)
	if err != nil || exists {
		return exists, err
	}
	for _, source := range entry.Sources {
		if strings.HasPrefix(source, "谁是卧底 #") {
			return true, nil
		}
	}
	return false, nil
}
