package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	usersvc "forest/go-api/internal/user"
)

const dispatchSampleRetention = 24 * time.Hour
const dispatchEventRetention = 3 * 24 * time.Hour

// No foreign keys to live resources: deleting/reconfiguring an entry or probe
// must not erase the snapshots that explain an earlier outage.
var dispatchHistorySchema = []string{
	`CREATE TABLE IF NOT EXISTS v2_dispatch_history (
 id BIGSERIAL PRIMARY KEY, source TEXT NOT NULL CHECK(source IN ('entry','pool')),
 target_id BIGINT NOT NULL, probe_id BIGINT NOT NULL, version BIGINT NOT NULL,
 run_id BIGINT NOT NULL, sequence BIGINT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('sample','event')),
 event_type TEXT NOT NULL DEFAULT '', host TEXT NOT NULL, port INTEGER NOT NULL,
 success BOOLEAN NOT NULL, payload JSONB NOT NULL, created_at BIGINT NOT NULL,
 UNIQUE(source,target_id,probe_id,version,run_id,sequence,kind))`,
	`CREATE INDEX IF NOT EXISTS idx_dispatch_history_time ON v2_dispatch_history(kind,created_at DESC,id DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_dispatch_history_target ON v2_dispatch_history(source,target_id,probe_id,kind,created_at DESC,id DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_dispatch_history_host ON v2_dispatch_history(host,kind,created_at DESC,id DESC)`,
}

type DispatchHistorySample struct {
	Source         string                `json:"source"`
	TargetID       int64                 `json:"target_id"`
	ProbeID        int64                 `json:"probe_id"`
	Version        int64                 `json:"version"`
	RunID          int64                 `json:"run_id"`
	Sequence       int64                 `json:"sequence"`
	Success        bool                  `json:"success"`
	LatencyMS      *int64                `json:"latency_ms"`
	Error          string                `json:"error"`
	ResolvedIP     string                `json:"resolved_ip"`
	ReportedAt     int64                 `json:"reported_at"`
	Streak         int64                 `json:"streak"`
	Host           string                `json:"host"`
	Port           int64                 `json:"port"`
	Name           string                `json:"name"`
	ProbeName      string                `json:"probe_name"`
	Status         string                `json:"status"`
	Ownership      usersvc.DispatchEntry `json:"ownership"`
	OwnershipKnown bool                  `json:"ownership_known"`
}

type DispatchHistoryRecord struct {
	DispatchHistorySample
	ID        int64  `json:"id"`
	Kind      string `json:"kind"`
	EventType string `json:"event_type"`
	CreatedAt int64  `json:"created_at"`
}

type DispatchHistoryRequest struct {
	Kind, Source, Host, EventType string
	ProbeID, From, To, Port       int64
	Success                       *bool
	Page                          int64
}

type DispatchHistoryResult struct {
	Data           []DispatchHistoryRecord `json:"data"`
	Total          int64                   `json:"total"`
	Page           int64                   `json:"page"`
	PageSize       int64                   `json:"page_size"`
	RetentionHours int64                   `json:"retention_hours"`
	WriterError    string                  `json:"writer_error,omitempty"`
}

type dispatchHistoryBatch struct {
	samples     []DispatchHistorySample
	scopes      map[string]usersvc.DispatchEntry
	scopesKnown bool
}

func (b *dispatchHistoryBatch) add(source string, probeID int64, r DNSProbeResult, now, streak int64) {
	if b == nil {
		return
	}
	sequence, _ := dispatchResultSequence(r)
	values := dnsProbeStateWriteValues(r)
	sample := DispatchHistorySample{Source: source, TargetID: r.TargetID, ProbeID: probeID, Version: r.TargetVersion, RunID: r.RunID, Sequence: sequence, Success: *r.Success, Error: values.Error, ResolvedIP: r.ResolvedIP, ReportedAt: now, Streak: streak}
	if sample.Success {
		sample.LatencyMS = r.LatencyMS
	}
	b.samples = append(b.samples, sample)
}

func (s *DBService) ensureDispatchHistorySchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return ErrUnavailable
	}
	s.dispatchHistoryMu.Lock()
	defer s.dispatchHistoryMu.Unlock()
	if s.dispatchHistorySchemaOK {
		return nil
	}
	for _, statement := range dispatchHistorySchema {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("初始化监控历史失败: %w", err)
		}
	}
	s.dispatchHistorySchemaOK = true
	return nil
}

func (s *DBService) setDispatchHistoryError(err error) {
	s.dispatchHistoryMu.Lock()
	if err == nil {
		s.dispatchHistoryLastError = ""
	} else {
		s.dispatchHistoryLastError = "检测历史记录失败，请检查服务日志；此期间历史可能不完整"
	}
	s.dispatchHistoryMu.Unlock()
	if err != nil {
		s.logDNSFailoverWorkerError("dispatch history write failed: %v", err)
	}
}

func (s *DBService) prepareDispatchHistory(ctx context.Context) *dispatchHistoryBatch {
	if !s.dispatchHistoryEnabled {
		return nil
	}
	historyCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := s.ensureDispatchHistorySchema(historyCtx); err != nil {
		s.setDispatchHistoryError(err)
		return nil
	}
	// Share the five-second catalog snapshot with task generation, never resolve
	// every user's ownership separately for every target or every sample.
	_, err := s.dispatchTaskHosts(historyCtx)
	s.dispatchCacheMu.Lock()
	scopes := s.dispatchCachedScopes
	s.dispatchCacheMu.Unlock()
	return &dispatchHistoryBatch{scopes: scopes, scopesKnown: err == nil && scopes != nil}
}

func dispatchHistoryTransition(previous *DispatchHistorySample, current *DispatchHistorySample, interval, timeout int64) string {
	fresh := previous != nil && previous.Version == current.Version && previous.RunID == current.RunID &&
		dispatchPoolStateFresh(sql.NullInt64{Int64: previous.ReportedAt, Valid: true}, current.ReportedAt, interval, timeout)
	current.Status = "healthy"
	if !current.Success {
		current.Status = "down"
	} else if current.Source == "pool" && current.Streak < 2 {
		current.Status = "checking"
		if fresh && previous.Status == "down" {
			current.Status = "down"
		}
	}
	if current.Status == "down" && !current.Success && (!fresh || previous.Status != "down") {
		return "down"
	}
	if fresh && previous.Status == "down" && current.Status == "healthy" {
		return "recovered"
	}
	return ""
}

// Optional diagnostic storage is isolated with a savepoint and bounded SQL
// timeouts. Failure cannot roll back already accepted live-monitor updates.
func (s *DBService) persistDispatchHistory(ctx context.Context, tx *sql.Tx, batch *dispatchHistoryBatch) {
	if batch == nil || len(batch.samples) == 0 {
		return
	}
	if _, err := tx.ExecContext(ctx, "SAVEPOINT dispatch_history"); err != nil {
		s.setDispatchHistoryError(err)
		return
	}
	err := s.writeDispatchHistory(ctx, tx, batch)
	if err != nil {
		if _, rollbackErr := tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT dispatch_history"); rollbackErr != nil {
			s.setDispatchHistoryError(rollbackErr)
			return
		}
	}
	if _, releaseErr := tx.ExecContext(ctx, "RELEASE SAVEPOINT dispatch_history"); releaseErr != nil {
		err = releaseErr
	}
	s.setDispatchHistoryError(err)
}

func (s *DBService) writeDispatchHistory(ctx context.Context, tx *sql.Tx, batch *dispatchHistoryBatch) error {
	var lockTimeout, statementTimeout string
	if err := tx.QueryRowContext(ctx, `SELECT current_setting('lock_timeout'),current_setting('statement_timeout')`).Scan(&lockTimeout, &statementTimeout); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('lock_timeout','200ms',true),set_config('statement_timeout','1000ms',true)`); err != nil {
		return err
	}
	raw, err := json.Marshal(batch.samples)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `WITH requested AS (
 SELECT * FROM jsonb_to_recordset($1::jsonb) AS r(source text,target_id bigint,probe_id bigint,version bigint,run_id bigint,sequence bigint)),
 targets AS (
 SELECT DISTINCT r.source,r.target_id,r.probe_id,m.host,m.check_port AS port,m.host AS name,m.check_interval_sec,m.tcp_timeout_ms,p.name AS probe_name
 FROM requested r JOIN v2_dispatch_monitor m ON m.id=r.target_id JOIN v2_dns_probe p ON p.id=r.probe_id WHERE r.source='entry'
 UNION ALL
 SELECT DISTINCT r.source,r.target_id,r.probe_id,t.host,t.port,t.name,t.check_interval_sec,t.tcp_timeout_ms,p.name
 FROM requested r JOIN v2_dispatch_check_target t ON t.id=r.target_id JOIN v2_dns_probe p ON p.id=r.probe_id WHERE r.source='pool' AND t.kind='pool')
 SELECT t.source,t.target_id,t.probe_id,t.host,t.port,t.name,t.probe_name,t.check_interval_sec,t.tcp_timeout_ms,h.payload
 FROM targets t LEFT JOIN LATERAL (SELECT payload FROM v2_dispatch_history
 WHERE source=t.source AND target_id=t.target_id AND probe_id=t.probe_id AND kind='sample'
 ORDER BY created_at DESC,id DESC LIMIT 1) h ON TRUE`, string(raw))
	if err != nil {
		return err
	}
	type key struct {
		source        string
		target, probe int64
	}
	type snapshot struct {
		host, name, probe       string
		port, interval, timeout int64
		previous                *DispatchHistorySample
	}
	snapshots := map[key]*snapshot{}
	for rows.Next() {
		var k key
		var x snapshot
		var previous []byte
		if err = rows.Scan(&k.source, &k.target, &k.probe, &x.host, &x.port, &x.name, &x.probe, &x.interval, &x.timeout, &previous); err != nil {
			break
		}
		if len(previous) > 0 {
			x.previous = &DispatchHistorySample{}
			if err = json.Unmarshal(previous, x.previous); err != nil {
				break
			}
		}
		snapshots[k] = &x
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	records := []DispatchHistoryRecord{}
	for _, sample := range batch.samples {
		x := snapshots[key{sample.Source, sample.TargetID, sample.ProbeID}]
		if x == nil {
			return fmt.Errorf("missing accepted target snapshot")
		}
		sample.Host, sample.Port, sample.Name, sample.ProbeName = x.host, x.port, x.name, x.probe
		sample.Ownership, sample.OwnershipKnown = batch.scopes[x.host], batch.scopesKnown
		sample.Ownership.Host = x.host
		event := dispatchHistoryTransition(x.previous, &sample, x.interval, x.timeout)
		record := DispatchHistoryRecord{DispatchHistorySample: sample, Kind: "sample", CreatedAt: sample.ReportedAt}
		records = append(records, record)
		if event != "" {
			record.Kind = "event"
			record.EventType = event
			records = append(records, record)
		}
		copy := sample
		x.previous = &copy
	}
	raw, err = json.Marshal(records)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO v2_dispatch_history(source,target_id,probe_id,version,run_id,sequence,kind,event_type,host,port,success,payload,created_at)
 SELECT r->>'source',(r->>'target_id')::bigint,(r->>'probe_id')::bigint,(r->>'version')::bigint,
 (r->>'run_id')::bigint,(r->>'sequence')::bigint,r->>'kind',r->>'event_type',r->>'host',(r->>'port')::integer,
 (r->>'success')::boolean,r,(r->>'created_at')::bigint FROM jsonb_array_elements($1::jsonb) r
 ON CONFLICT(source,target_id,probe_id,version,run_id,sequence,kind) DO NOTHING`, string(raw))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `SELECT set_config('lock_timeout',$1,true),set_config('statement_timeout',$2,true)`, lockTimeout, statementTimeout)
	return err
}

func (s *DBService) ListDispatchHistory(ctx context.Context, req DispatchHistoryRequest) (DispatchHistoryResult, error) {
	result := DispatchHistoryResult{Data: []DispatchHistoryRecord{}, Page: req.Page, PageSize: 50}
	if req.Kind == "" {
		req.Kind = "sample"
	}
	if (req.Kind != "sample" && req.Kind != "event") || (req.Source != "" && req.Source != "entry" && req.Source != "pool") || req.Page < 1 || req.Page > 100000 || req.ProbeID < 0 || req.Port < 0 || req.Port > 65535 || req.From < 0 || req.To < 0 || (req.From > 0 && req.To > 0 && req.From > req.To) || len(req.Host) > 253 || (req.EventType != "" && req.EventType != "down" && req.EventType != "recovered") {
		return result, ErrDNSProbeInvalidRequest
	}
	if err := s.ensureDispatchHistorySchema(ctx); err != nil {
		return result, err
	}
	retention := dispatchSampleRetention
	if req.Kind == "event" {
		retention = dispatchEventRetention
	}
	result.RetentionHours = int64(retention / time.Hour)
	from := max(time.Now().Add(-retention).Unix(), req.From)
	args := []any{req.Kind, from}
	conditions := []string{"kind=$1", "created_at>=$2"}
	add := func(column string, value any) {
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf("%s=$%d", column, len(args)))
	}
	if req.Source != "" {
		add("source", req.Source)
	}
	if req.Host != "" {
		add("host", strings.TrimSpace(req.Host))
	}
	if req.Port > 0 {
		add("port", req.Port)
	}
	if req.ProbeID > 0 {
		add("probe_id", req.ProbeID)
	}
	if req.Success != nil {
		add("success", *req.Success)
	}
	if req.EventType != "" {
		add("event_type", req.EventType)
	}
	if req.To > 0 {
		args = append(args, req.To)
		conditions = append(conditions, fmt.Sprintf("created_at<=$%d", len(args)))
	}
	where := " WHERE " + strings.Join(conditions, " AND ")
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM v2_dispatch_history`+where, args...).Scan(&result.Total); err != nil {
		return result, err
	}
	args = append(args, result.PageSize, (req.Page-1)*result.PageSize)
	rows, err := s.db.QueryContext(ctx, `SELECT id,kind,event_type,payload,created_at FROM v2_dispatch_history`+where+fmt.Sprintf(" ORDER BY created_at DESC,id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var record DispatchHistoryRecord
		var payload []byte
		if err = rows.Scan(&record.ID, &record.Kind, &record.EventType, &payload, &record.CreatedAt); err != nil {
			return result, err
		}
		if err = json.Unmarshal(payload, &record.DispatchHistorySample); err != nil {
			return result, err
		}
		result.Data = append(result.Data, record)
	}
	s.dispatchHistoryMu.Lock()
	result.WriterError = s.dispatchHistoryLastError
	s.dispatchHistoryMu.Unlock()
	return result, rows.Err()
}

func (s *DBService) cleanupDispatchHistory(ctx context.Context) error {
	if !s.dispatchHistoryEnabled {
		return nil
	}
	cleanupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := s.ensureDispatchHistorySchema(cleanupCtx); err != nil {
		return err
	}
	for _, item := range []struct {
		kind      string
		retention time.Duration
	}{{"sample", dispatchSampleRetention}, {"event", dispatchEventRetention}} {
		query := `WITH doomed AS (SELECT id FROM v2_dispatch_history WHERE kind='` + item.kind + `' AND created_at<$1 ORDER BY created_at,id LIMIT $2) DELETE FROM v2_dispatch_history WHERE id IN(SELECT id FROM doomed)`
		if err := deleteDNSFailoverRetentionRows(cleanupCtx, s.db, query, time.Now().Add(-item.retention).Unix(), 5000); err != nil {
			return err
		}
	}
	return nil
}
